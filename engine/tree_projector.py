import os
import re
import subprocess
from typing import Dict, List, Tuple, Set
from engine.git_adapter import GitAdapter, GitError
from engine.exclude_engine import ExcludeEngine, ExcludeDecision

class TreeProjectionError(Exception):
    pass

class TreeProjector:
    def __init__(self, source_git: GitAdapter, target_git: GitAdapter, exclude_engine: ExcludeEngine):
        self.source_git = source_git
        self.target_git = target_git
        self.exclude_engine = exclude_engine
        self.objects_streamed = False
        # 记录包含被 PRUNE 文件的目录前缀，仅对这些目录执行递归过滤
        self.dirty_dirs: Set[str] = {"docs"}
        self._subtree_cache: Dict[Tuple[str, str], str] = {}

    def _mark_dirty_ancestors(self, path: str):
        parts = path.split("/")
        for i in range(1, len(parts)):
            self.dirty_dirs.add("/".join(parts[:i]))

    def stream_approved_objects(self, base_commit: str, tip_commit: str):
        """
        Streams approved objects from source to target using native Git pack pipe.
        Ensures target export store has all approved Blobs and Subtrees without unapproved items.
        """
        if self.objects_streamed:
            return

        # 1. Collect all objects created in the pending range
        raw_objs = self.source_git._run(["rev-list", "--objects", f"{base_commit}..{tip_commit}"])[0]
        approved_oids = []

        for line in raw_objs.decode("utf-8", errors="replace").strip().splitlines():
            if not line:
                continue
            parts = line.split(maxsplit=1)
            oid = parts[0]
            path = parts[1] if len(parts) > 1 else ""

            # 跳过源库 Commit 对象和未脱敏的根 Tree 对象
            if not path:
                continue

            decision, _, _ = self.exclude_engine.evaluate_path(path)
            if decision == ExcludeDecision.PRUNE:
                self._mark_dirty_ancestors(path)
                continue

            approved_oids.append(oid)

        # 2. Pipe approved objects into target repo
        if approved_oids:
            oids_data = "\n".join(approved_oids).encode("ascii") + b"\n"
            p_pack = subprocess.Popen(
                ["git", "-C", self.source_git.repo_dir, "pack-objects", "--stdout"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            pack_data, pack_err = p_pack.communicate(input=oids_data)
            if p_pack.returncode != 0:
                raise TreeProjectionError(f"Failed to pack approved objects: {pack_err.decode(errors='replace')}")

            p_unpack = subprocess.Popen(
                ["git", "-C", self.target_git.repo_dir, "unpack-objects"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            _, unpack_err = p_unpack.communicate(input=pack_data)
            if p_unpack.returncode != 0:
                raise TreeProjectionError(f"Failed to unpack approved objects: {unpack_err.decode(errors='replace')}")

        self.objects_streamed = True

    def _safe_mktree_z(self, records: List[Tuple[str, str, str, str]]) -> str:
        """
        Calls target_git.mktree_z. If a historical object is missing in target_git,
        streams that missing object tree/blob from source_git on-demand and retries.
        """
        while True:
            try:
                return self.target_git.mktree_z(records)
            except GitError as e:
                m = re.search(r"object ([0-9a-f]{40}) is unavailable", str(e))
                if not m:
                    raise
                missing_oid = m.group(1)
                self._copy_missing_object_closure(missing_oid)

    def _copy_missing_object_closure(self, oid: str):
        """Copies a missing blob or subtree from source_git to target_git via pack-objects."""
        raw_objs = self.source_git._run(["rev-list", "--objects", oid])[0]
        oids_to_pack = []
        for line in raw_objs.decode("utf-8", errors="replace").strip().splitlines():
            if not line:
                continue
            oids_to_pack.append(line.split(maxsplit=1)[0])

        if oids_to_pack:
            oids_data = "\n".join(oids_to_pack).encode("ascii") + b"\n"
            p_pack = subprocess.Popen(
                ["git", "-C", self.source_git.repo_dir, "pack-objects", "--stdout"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            pack_data, _ = p_pack.communicate(input=oids_data)
            p_unpack = subprocess.Popen(
                ["git", "-C", self.target_git.repo_dir, "unpack-objects"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            p_unpack.communicate(input=pack_data)

    def project_commit_tree(self, commit_oid: str) -> str:
        """
        Projects a clean, excluded Git Tree for commit_oid directly into target object store.
        Returns: projected_root_tree_oid
        """
        root_entries = self.source_git._run(["ls-tree", "-z", f"{commit_oid}^{{tree}}"])[0].split(b"\0")
        safe_root = []

        for entry in root_entries:
            if not entry:
                continue
            meta, path_b = entry.split(b"\t", 1)
            path_str = path_b.decode("utf-8", errors="replace")
            m, t, o = meta.split()
            mode_str = m.decode("ascii")
            type_str = t.decode("ascii")
            oid_str = o.decode("ascii")

            # Check root-level exclusions (e.g. gwp_debug)
            decision, rule_id, details = self.exclude_engine.evaluate_path(path_str, mode=mode_str)
            if decision == ExcludeDecision.PRUNE:
                self.exclude_engine.record_audit(commit_oid, path_str, "PRUNE", rule_id, details)
                continue

            if path_str == "app":
                # Handle app directory: keep only mickey_smart and Makefile
                app_entries = self.source_git._run(["ls-tree", "-z", oid_str])[0].split(b"\0")
                filtered_app = []
                for ae in app_entries:
                    if not ae:
                        continue
                    ameta, apath_b = ae.split(b"\t", 1)
                    apath_str = apath_b.decode("utf-8", errors="replace")
                    app_full_path = f"app/{apath_str}"
                    am, at, ao = ameta.split()
                    am_str = am.decode("ascii")
                    at_str = at.decode("ascii")
                    ao_str = ao.decode("ascii")

                    dec, rid, det = self.exclude_engine.evaluate_path(app_full_path, mode=am_str)
                    if dec == ExcludeDecision.PRUNE:
                        self.exclude_engine.record_audit(commit_oid, app_full_path, "PRUNE", rid, det)
                        continue

                    if at_str == "tree" and app_full_path in self.dirty_dirs:
                        ao_str = self._filter_subtree(commit_oid, app_full_path, ao_str)

                    filtered_app.append((am_str, at_str, ao_str, apath_str))

                new_app_oid = self._safe_mktree_z(filtered_app)
                safe_root.append(("040000", "tree", new_app_oid, "app"))

            elif type_str == "tree" and path_str in self.dirty_dirs:
                new_sub_oid = self._filter_subtree(commit_oid, path_str, oid_str)
                safe_root.append((mode_str, "tree", new_sub_oid, path_str))

            else:
                safe_root.append((mode_str, type_str, oid_str, path_str))

        root_tree_oid = self._safe_mktree_z(safe_root)
        return root_tree_oid

    def _filter_subtree(self, commit_oid: str, dir_path: str, tree_oid: str) -> str:
        cache_key = (dir_path, tree_oid)
        if cache_key in self._subtree_cache:
            return self._subtree_cache[cache_key]

        entries = self.source_git._run(["ls-tree", "-z", tree_oid])[0].split(b"\0")
        filtered = []
        for entry in entries:
            if not entry:
                continue
            meta, path_b = entry.split(b"\t", 1)
            name_str = path_b.decode("utf-8", errors="replace")
            full_path = f"{dir_path}/{name_str}"
            m, t, o = meta.split()
            mode_str = m.decode("ascii")
            type_str = t.decode("ascii")
            oid_str = o.decode("ascii")

            if type_str == "tree":
                if full_path in self.dirty_dirs:
                    oid_str = self._filter_subtree(commit_oid, full_path, oid_str)
                filtered.append((mode_str, type_str, oid_str, name_str))
            else:
                dec, rid, det = self.exclude_engine.evaluate_path(full_path, mode=mode_str)
                if dec == ExcludeDecision.PRUNE:
                    self.exclude_engine.record_audit(commit_oid, full_path, "PRUNE", rid, det)
                    continue
                filtered.append((mode_str, type_str, oid_str, name_str))

        projected_oid = self._safe_mktree_z(filtered)
        self._subtree_cache[cache_key] = projected_oid
        return projected_oid