import subprocess
import os
from typing import List, Dict, Tuple, Optional


class GitError(Exception):
    pass


class GitAdapter:
    def __init__(self, repo_dir: str):
        self.repo_dir = os.path.abspath(repo_dir)
        dot_git = os.path.join(self.repo_dir, ".git")
        is_worktree_repo = os.path.isdir(dot_git) or os.path.isfile(dot_git)
        is_bare_repo = os.path.isdir(os.path.join(self.repo_dir, "objects")) and os.path.isfile(
            os.path.join(self.repo_dir, "HEAD")
        )
        if not (is_worktree_repo or is_bare_repo):
            raise GitError(f"Not a valid git repository: {self.repo_dir}")

    def _run(
        self,
        args: List[str],
        stdin_bytes: Optional[bytes] = None,
        env: Optional[dict] = None,
    ) -> Tuple[bytes, bytes, int]:
        run_env = os.environ.copy()
        if env:
            run_env.update(env)
        cmd = ["git", "-C", self.repo_dir] + args
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE if stdin_bytes is not None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=run_env,
            )
            stdout, stderr = proc.communicate(input=stdin_bytes)
            return stdout, stderr, proc.returncode
        except Exception as e:
            raise GitError(f"Failed to execute git command {cmd}: {e}")

    def _run_checked(
        self,
        args: List[str],
        stdin_bytes: Optional[bytes] = None,
        env: Optional[dict] = None,
    ) -> bytes:
        stdout, stderr, code = self._run(args, stdin_bytes=stdin_bytes, env=env)
        if code != 0:
            err_msg = stderr.decode("utf-8", errors="replace").strip()
            raise GitError(
                f"Git command failed (exit={code}) in '{self.repo_dir}': git {' '.join(args)} -> {err_msg}"
            )
        return stdout

    def rev_parse(self, rev: str, env: Optional[dict] = None) -> str:
        stdout = self._run_checked(["rev-parse", rev], env=env)
        return stdout.decode("utf-8", errors="strict").strip()

    def rev_list_topo(
        self, base_commit: str, tip_commit: str, env: Optional[dict] = None
    ) -> List[str]:
        # rev-list --topo-order --reverse base..tip
        arg = f"{base_commit}..{tip_commit}"
        stdout = self._run_checked(
            ["rev-list", "--topo-order", "--reverse", arg], env=env
        )
        lines = stdout.decode("utf-8", errors="strict").strip().splitlines()
        return [l.strip() for l in lines if l.strip()]

    def get_commit_parents(
        self, commit_oid: str, env: Optional[dict] = None
    ) -> List[str]:
        stdout = self._run_checked(
            ["rev-list", "--parents", "-n", "1", commit_oid], env=env
        )
        parts = stdout.decode("utf-8", errors="strict").strip().split()
        return parts[1:] if len(parts) > 1 else []

    def get_commit_metadata(
        self, commit_oid: str, env: Optional[dict] = None
    ) -> dict:
        # format: %an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%B
        fmt = "%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%B"
        stdout = self._run_checked(
            ["log", "-1", f"--format={fmt}", commit_oid], env=env
        )
        parts = stdout.split(b"\x00")
        if len(parts) < 7:
            raise GitError(f"Unexpected metadata split count for commit {commit_oid}")
        return {
            "commit_oid": commit_oid,
            "author_name": parts[0].decode("utf-8", errors="replace"),
            "author_email": parts[1].decode("utf-8", errors="replace"),
            "author_date": parts[2].decode("utf-8", errors="replace"),
            "committer_name": parts[3].decode("utf-8", errors="replace"),
            "committer_email": parts[4].decode("utf-8", errors="replace"),
            "committer_date": parts[5].decode("utf-8", errors="replace"),
            "message": parts[6].decode("utf-8", errors="replace"),
        }

    def ls_tree_z(self, tree_ish: str, env: Optional[dict] = None) -> List[dict]:
        stdout = self._run_checked(["ls-tree", "-z", tree_ish], env=env)
        entries = []
        raw_chunks = stdout.split(b"\x00")
        for chunk in raw_chunks:
            if not chunk:
                continue
            tab_idx = chunk.find(b"\t")
            if tab_idx == -1:
                raise GitError(f"Malformed ls-tree entry for {tree_ish}: {chunk!r}")
            try:
                meta = chunk[:tab_idx].decode("ascii", errors="strict").split()
                name_str = chunk[tab_idx + 1 :].decode("utf-8", errors="strict")
            except UnicodeDecodeError as e:
                raise GitError(
                    f"Strict UTF-8 decode failed in ls-tree for {tree_ish}: {e}"
                ) from e
            if len(meta) < 3:
                raise GitError(f"Malformed ls-tree metadata for {tree_ish}: {meta!r}")
            entries.append(
                {
                    "mode": meta[0],
                    "type": meta[1],
                    "oid": meta[2],
                    "name": name_str,
                }
            )
        return entries

    def ls_tree_r_z(self, tree_ish: str, env: Optional[dict] = None) -> List[dict]:
        stdout = self._run_checked(["ls-tree", "-r", "-z", tree_ish], env=env)
        entries = []
        raw_chunks = stdout.split(b"\x00")
        for chunk in raw_chunks:
            if not chunk:
                continue
            tab_idx = chunk.find(b"\t")
            if tab_idx == -1:
                raise GitError(f"Malformed ls-tree -r entry for {tree_ish}: {chunk!r}")
            try:
                meta = chunk[:tab_idx].decode("ascii", errors="strict").split()
                path_str = chunk[tab_idx + 1 :].decode("utf-8", errors="strict")
            except UnicodeDecodeError as e:
                raise GitError(
                    f"Strict UTF-8 decode failed in ls-tree -r for {tree_ish}: {e}"
                ) from e
            if len(meta) < 3:
                raise GitError(
                    f"Malformed ls-tree -r metadata for {tree_ish}: {meta!r}"
                )
            entries.append(
                {
                    "mode": meta[0],
                    "type": meta[1],
                    "oid": meta[2],
                    "path": path_str,
                }
            )
        return entries

    def ls_tree_r_z_strict(
        self, tree_ish: str, env: Optional[dict] = None
    ) -> List[dict]:
        return self.ls_tree_r_z(tree_ish, env=env)

    def cat_file_blob(self, blob_oid: str, env: Optional[dict] = None) -> bytes:
        return self._run_checked(["cat-file", "-p", blob_oid], env=env)

    def has_object(self, oid: str, env: Optional[dict] = None) -> bool:
        _, _, code = self._run(["cat-file", "-e", oid], env=env)
        return code == 0

    def hash_object_write(self, data: bytes, env: Optional[dict] = None) -> str:
        stdout = self._run_checked(
            ["hash-object", "-w", "--stdin"], stdin_bytes=data, env=env
        )
        return stdout.decode("utf-8", errors="strict").strip()

    def mktree_z(
        self, records: List[Tuple[str, str, str, str]], env: Optional[dict] = None
    ) -> str:
        # records format: (mode, type, oid, basename)
        # NUL-delimited input format: <mode> <type> <oid>\t<basename>\0
        buf = bytearray()
        for mode, type_, oid, basename in records:
            entry = f"{mode} {type_} {oid}\t{basename}\0".encode("utf-8")
            buf.extend(entry)
        stdout = self._run_checked(["mktree", "-z"], stdin_bytes=bytes(buf), env=env)
        return stdout.decode("utf-8", errors="strict").strip()

    def commit_tree(
        self,
        tree_oid: str,
        parents: List[str],
        message: str,
        env: Optional[dict] = None,
    ) -> str:
        args = ["commit-tree", tree_oid]
        for p in parents:
            args.extend(["-p", p])
        msg_bytes = message.encode("utf-8")
        stdout = self._run_checked(args, stdin_bytes=msg_bytes, env=env)
        return stdout.decode("utf-8", errors="strict").strip()

    def update_ref(
        self,
        ref_name: str,
        new_oid: str,
        old_oid: Optional[str] = None,
        env: Optional[dict] = None,
    ) -> None:
        args = ["update-ref", ref_name, new_oid]
        if old_oid:
            args.append(old_oid)
        self._run_checked(args, env=env)

    def merge_base_is_ancestor(self, ancestor_oid: str, descendant_oid: str) -> bool:
        _, _, code = self._run(
            ["merge-base", "--is-ancestor", ancestor_oid, descendant_oid]
        )
        return code == 0

    def check_is_ancestor_tri_state(
        self,
        ancestor_oid: str,
        descendant_oid: str,
        remote_for_missing: Optional[str] = None,
        remote_ref_for_missing: Optional[str] = None,
    ) -> str:
        if not ancestor_oid or not descendant_oid:
            return "UNKNOWN"
        if not (self.has_object(ancestor_oid) and self.has_object(descendant_oid)):
            if remote_for_missing and remote_ref_for_missing:
                clean_ref = remote_ref_for_missing.lstrip("+")
                try:
                    self.fetch_ref(
                        remote_for_missing,
                        f"+{clean_ref}:refs/sync/probe_remote_tip",
                    )
                except GitError:
                    return "UNKNOWN"
            if not (self.has_object(ancestor_oid) and self.has_object(descendant_oid)):
                return "UNKNOWN"

        _, _, code = self._run(
            ["merge-base", "--is-ancestor", ancestor_oid, descendant_oid]
        )
        if code == 0:
            return "TRUE"
        if code == 1:
            return "FALSE"
        return "UNKNOWN"

    def diff_tree_raw(
        self, old_tree: str, new_tree: str, env: Optional[dict] = None
    ) -> List[dict]:
        stdout = self._run_checked(
            ["diff-tree", "-r", "--raw", "-z", "--no-renames", old_tree, new_tree],
            env=env,
        )
        results = []
        raw_chunks = stdout.split(b"\x00")
        i = 0
        while i < len(raw_chunks):
            chunk = raw_chunks[i]
            if not chunk:
                i += 1
                continue
            if not chunk.startswith(b":"):
                raise GitError(
                    f"Malformed diff-tree metadata chunk between {old_tree} and {new_tree}: {chunk!r}"
                )
            try:
                meta = chunk.decode("ascii", errors="strict").split()
            except UnicodeDecodeError as e:
                raise GitError(
                    f"Strict ASCII decode failed in diff-tree metadata between {old_tree} and {new_tree}: {e}"
                ) from e
            if len(meta) < 5:
                raise GitError(
                    f"Incomplete diff-tree metadata between {old_tree} and {new_tree}: {meta!r}"
                )
            i += 1
            if i >= len(raw_chunks):
                raise GitError(
                    f"Truncated diff-tree output (missing path) between {old_tree} and {new_tree}"
                )
            try:
                path = raw_chunks[i].decode("utf-8", errors="strict")
            except UnicodeDecodeError as e:
                raise GitError(
                    f"Strict UTF-8 decode failed in diff-tree path between {old_tree} and {new_tree}: {e}"
                ) from e
            results.append(
                {
                    "old_mode": meta[0][1:] if meta[0].startswith(":") else meta[0],
                    "new_mode": meta[1],
                    "old_oid": meta[2],
                    "new_oid": meta[3],
                    "status": meta[4],
                    "path": path,
                }
            )
            i += 1
        return results

    def diff_tree_raw_strict(
        self, old_tree: str, new_tree: str, env: Optional[dict] = None
    ) -> List[dict]:
        return self.diff_tree_raw(old_tree, new_tree, env=env)

    def ls_remote_ref(self, remote: str, ref: str) -> Optional[str]:
        stdout = self._run_checked(["ls-remote", remote, ref])
        text = stdout.decode("utf-8", errors="strict").strip()
        if not text:
            return None
        for line in text.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2 and parts[1] == ref:
                return parts[0]
        return None

    def fetch_ref(self, remote: str, refspec: str) -> None:
        self._run_checked(["fetch", "--no-tags", remote, refspec])

    def get_remote_url(self, remote: str = "origin", push: bool = False) -> str:
        args = ["remote", "get-url"]
        if push:
            args.append("--push")
        args.append(remote)
        stdout = self._run_checked(args)
        return stdout.decode("utf-8", errors="strict").strip()

    def get_symbolic_head(self) -> Optional[str]:
        stdout, stderr, code = self._run(["symbolic-ref", "-q", "HEAD"])
        if code == 0:
            val = stdout.decode("utf-8", errors="strict").strip()
            return val if val else None
        if code == 1:
            return None
        err_msg = stderr.decode("utf-8", errors="replace").strip()
        raise GitError(
            f"Git symbolic-ref failed (exit={code}) in '{self.repo_dir}': {err_msg}"
        )

    def read_tree(self, tree_ish: str, env: Optional[dict] = None) -> None:
        self._run_checked(["read-tree", tree_ish], env=env)

    def status_porcelain_z(self) -> List[bytes]:
        stdout = self._run_checked(
            ["status", "--porcelain", "-z", "--untracked-files=all"]
        )
        return [entry for entry in stdout.split(b"\x00") if entry]

    def push_ref(
        self,
        remote: str,
        src_ref: str,
        dst_ref: str,
        no_follow_tags: bool = True,
        dry_run: bool = False,
        expected_old_remote_oid: Optional[str] = None,
    ) -> Tuple[bool, str]:
        refspec = f"{src_ref}:{dst_ref}"
        args = ["push", remote, refspec]
        if no_follow_tags:
            args.append("--no-follow-tags")
        if dry_run:
            args.append("--dry-run")
        if expected_old_remote_oid is not None:
            args.append(f"--force-with-lease={dst_ref}:{expected_old_remote_oid}")
        stdout, stderr, code = self._run(args)
        out_msg = (stdout + b"\n" + stderr).decode("utf-8", errors="replace").strip()
        return (code == 0), out_msg
