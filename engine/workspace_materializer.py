import os
import time
from typing import Dict, List, Tuple
from engine.git_adapter import GitAdapter, GitError

class MaterializeError(Exception):
    pass

class WorkspaceMaterializer:
    def __init__(self, target_git: GitAdapter, target_worktree: str):
        self.target_git = target_git
        self.target_worktree = os.path.abspath(target_worktree)
        self.lock_backoff = [0.2, 0.5, 1.0, 2.0]

    def materialize_delta(self, old_tree_oid: str, new_tree_oid: str) -> Dict[str, int]:
        """
        Diffs old_tree and new_tree, executes deletions first, then safely writes added/modified
        files from trusted Git Blobs and triggers DLP in-place write.
        Returns: summary dict {"added": count, "modified": count, "deleted": count}
        """
        raw_diff = self.target_git.diff_tree_raw(old_tree_oid, new_tree_oid)
        deletions = []
        additions_and_mods = []

        for item in raw_diff:
            status = item["status"]
            if status == "D":
                deletions.append(item)
            elif status in ("A", "M", "T"):
                additions_and_mods.append(item)

        # 1. Execute deletions first
        for item in deletions:
            rel_path = item["path"]
            abs_path = os.path.join(self.target_worktree, rel_path)
            if os.path.isfile(abs_path) or os.path.islink(abs_path):
                self._safe_remove_file(abs_path)

        # 2. Materialize added / modified / type-changed files
        for item in additions_and_mods:
            rel_path = item["path"]
            new_oid = item["new_oid"]
            new_mode = item["new_mode"]
            abs_path = os.path.join(self.target_worktree, rel_path)

            os.makedirs(os.path.dirname(abs_path), exist_ok=True)
            blob_bytes = self.target_git.cat_file_blob(new_oid)

            if new_mode == "120000":
                # Symbolic link on Windows: write as small text file containing relative target
                self._safe_write_bytes(abs_path, blob_bytes, is_symlink=True)
            else:
                # Ordinary file: write from trusted Blob, then in-place rewrite for DLP
                self._safe_write_bytes(abs_path, blob_bytes, is_symlink=False)

        return {
            "added": sum(1 for x in additions_and_mods if x["status"] == "A"),
            "modified": sum(1 for x in additions_and_mods if x["status"] == "M"),
            "deleted": len(deletions),
            "type_changed": sum(1 for x in additions_and_mods if x["status"] == "T")
        }

    def _safe_remove_file(self, abs_path: str):
        for delay in self.lock_backoff:
            try:
                os.remove(abs_path)
                return
            except PermissionError:
                time.sleep(delay)
            except FileNotFoundError:
                return
        try:
            os.remove(abs_path)
        except Exception as e:
            raise MaterializeError(f"Failed to remove file '{abs_path}' due to lock/permission: {e}")

    def _safe_write_bytes(self, abs_path: str, data: bytes, is_symlink: bool = False):
        # Write bytes with retry on Windows file lock
        for delay in self.lock_backoff:
            try:
                with open(abs_path, "wb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())

                # If ordinary file, do a secondary in-place rewrite to trigger Windows DLP driver
                if not is_symlink:
                    with open(abs_path, "rb") as f:
                        read_data = f.read()
                    with open(abs_path, "wb") as f:
                        f.write(read_data)
                        f.flush()
                        os.fsync(f.fileno())
                return
            except PermissionError:
                time.sleep(delay)
            except Exception as e:
                time.sleep(delay)

        # Final attempt
        try:
            with open(abs_path, "wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
        except Exception as e:
            raise MaterializeError(f"Failed to write file '{abs_path}': {e}")
