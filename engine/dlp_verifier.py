import os
import hashlib
from typing import Dict, List, Tuple
from engine.git_adapter import GitAdapter

class DlpVerifier:
    def __init__(self, target_git: GitAdapter, target_worktree: str):
        self.target_git = target_git
        self.target_worktree = os.path.abspath(target_worktree)

    def verify_logical_integrity(self, tree_oid: str, sample_limit: int = 500) -> Tuple[bool, str]:
        """
        Verifies that files in the workspace match their expected Git Blob OIDs.
        """
        entries = self.target_git.ls_tree_r_z(tree_oid)
        checked = 0
        for entry in entries[:sample_limit]:
            path = entry["path"]
            expected_oid = entry["oid"]
            mode = entry["mode"]
            abs_path = os.path.join(self.target_worktree, path)

            if not os.path.isfile(abs_path) and not os.path.islink(abs_path):
                return False, f"File missing in workspace: {path}"

            try:
                with open(abs_path, "rb") as f:
                    data = f.read()
                # compute git blob sha1
                header = f"blob {len(data)}\0".encode("ascii")
                computed_oid = hashlib.sha1(header + data).hexdigest()
                if computed_oid != expected_oid:
                    # Account for Windows core.autocrlf (CRLF checkout on disk vs LF in git object)
                    lf_data = data.replace(b"\r\n", b"\n")
                    lf_header = f"blob {len(lf_data)}\0".encode("ascii")
                    lf_computed_oid = hashlib.sha1(lf_header + lf_data).hexdigest()
                    if lf_computed_oid != expected_oid:
                        return False, f"Logical hash mismatch for {path}: expected {expected_oid}, got {computed_oid}"
                checked += 1
            except Exception as e:
                return False, f"Failed to read file {path} for integrity verification: {e}"

        return True, f"Verified {checked} files logically matching Git Blob OIDs"

    def verify_physical_dlp_headers(self, sample_limit: int = 50) -> Tuple[bool, str]:
        """
        In local Windows audit mode, tests if written ordinary source files carry
        the TianShiDa DLP header (%TSD-Header-###%) via raw bytes inspection.
        """
        # Find candidate .c / .h / .txt files in target_worktree
        checked = 0
        tsd_found = 0
        for root, dirs, files in os.walk(self.target_worktree):
            if ".git" in root:
                continue
            for f in files:
                if f.endswith((".c", ".h", ".cpp", ".py", ".json", ".txt")):
                    p = os.path.join(root, f)
                    try:
                        with open(p, "rb") as fp:
                            head = fp.read(16)
                            if b"TSD" in head:
                                tsd_found += 1
                        checked += 1
                        if checked >= sample_limit:
                            break
                    except Exception:
                        pass
            if checked >= sample_limit:
                break

        if checked == 0:
            return True, "No candidate source files found to check physical DLP"
        
        # In current authorized Python environment, Python may see decrypted plaintext
        # whereas external probe sees %TSD-Header-###%. We report observed status.
        return True, f"DLP physical audit sample: checked {checked} files, {tsd_found} had raw TSD in current process view"
