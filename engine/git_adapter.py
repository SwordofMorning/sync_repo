import subprocess
import os
from typing import List, Dict, Tuple, Optional

class GitError(Exception):
    pass

class GitAdapter:
    def __init__(self, repo_dir: str):
        self.repo_dir = os.path.abspath(repo_dir)
        if not os.path.isdir(os.path.join(self.repo_dir, ".git")):
            raise GitError(f"Not a valid git repository: {self.repo_dir}")

    def _run(self, args: List[str], stdin_bytes: Optional[bytes] = None, env: Optional[dict] = None) -> Tuple[bytes, bytes, int]:
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
                env=run_env
            )
            stdout, stderr = proc.communicate(input=stdin_bytes)
            return stdout, stderr, proc.returncode
        except Exception as e:
            raise GitError(f"Failed to execute git command {cmd}: {e}")

    def rev_parse(self, rev: str) -> str:
        stdout, stderr, code = self._run(["rev-parse", rev])
        if code != 0:
            raise GitError(f"Failed to rev-parse '{rev}': {stderr.decode('utf-8', errors='ignore').strip()}")
        return stdout.decode("utf-8").strip()

    def rev_list_topo(self, base_commit: str, tip_commit: str) -> List[str]:
        # rev-list --topo-order --reverse base..tip
        arg = f"{base_commit}..{tip_commit}"
        stdout, stderr, code = self._run(["rev-list", "--topo-order", "--reverse", arg])
        if code != 0:
            raise GitError(f"Failed rev-list for '{arg}': {stderr.decode('utf-8', errors='ignore').strip()}")
        lines = stdout.decode("utf-8").strip().splitlines()
        return [l.strip() for l in lines if l.strip()]

    def get_commit_parents(self, commit_oid: str) -> List[str]:
        stdout, stderr, code = self._run(["rev-list", "--parents", "-n", "1", commit_oid])
        if code != 0:
            raise GitError(f"Failed to get parents for commit {commit_oid}: {stderr.decode('utf-8', errors='ignore')}")
        parts = stdout.decode("utf-8").strip().split()
        return parts[1:] if len(parts) > 1 else []

    def get_commit_metadata(self, commit_oid: str) -> dict:
        # format: %an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%B
        fmt = "%an%x00%ae%x00%aI%x00%cn%x00%ce%x00%cI%x00%B"
        stdout, stderr, code = self._run(["log", "-1", f"--format={fmt}", commit_oid])
        if code != 0:
            raise GitError(f"Failed to get metadata for commit {commit_oid}: {stderr.decode('utf-8', errors='ignore')}")
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
            "message": parts[6].decode("utf-8", errors="replace")
        }

    def ls_tree_r_z(self, tree_ish: str) -> List[dict]:
        stdout, stderr, code = self._run(["ls-tree", "-r", "-z", tree_ish])
        if code != 0:
            raise GitError(f"Failed ls-tree for {tree_ish}: {stderr.decode('utf-8', errors='ignore')}")
        entries = []
        raw_chunks = stdout.split(b"\x00")
        for chunk in raw_chunks:
            if not chunk:
                continue
            tab_idx = chunk.find(b"\t")
            if tab_idx == -1:
                continue
            meta = chunk[:tab_idx].decode("ascii", errors="replace").split()
            path_bytes = chunk[tab_idx + 1:]
            path_str = path_bytes.decode("utf-8", errors="replace")
            if len(meta) >= 3:
                entries.append({
                    "mode": meta[0],
                    "type": meta[1],
                    "oid": meta[2],
                    "path": path_str
                })
        return entries

    def cat_file_blob(self, blob_oid: str) -> bytes:
        stdout, stderr, code = self._run(["cat-file", "-p", blob_oid])
        if code != 0:
            raise GitError(f"Failed to cat-file blob {blob_oid}: {stderr.decode('utf-8', errors='ignore')}")
        return stdout

    def has_object(self, oid: str) -> bool:
        _, _, code = self._run(["cat-file", "-e", oid])
        return code == 0

    def hash_object_write(self, data: bytes) -> str:
        stdout, stderr, code = self._run(["hash-object", "-w", "--stdin"], stdin_bytes=data)
        if code != 0:
            raise GitError(f"Failed hash-object write: {stderr.decode('utf-8', errors='ignore')}")
        return stdout.decode("utf-8").strip()

    def mktree_z(self, records: List[Tuple[str, str, str, str]]) -> str:
        # records format: (mode, type, oid, basename)
        # NUL-delimited input format: <mode> <type> <oid>\t<basename>\0
        buf = bytearray()
        for mode, type_, oid, basename in records:
            entry = f"{mode} {type_} {oid}\t{basename}\0".encode("utf-8")
            buf.extend(entry)
        stdout, stderr, code = self._run(["mktree", "-z"], stdin_bytes=bytes(buf))
        if code != 0:
            raise GitError(f"Failed mktree: {stderr.decode('utf-8', errors='ignore')}")
        return stdout.decode("utf-8").strip()

    def commit_tree(self, tree_oid: str, parents: List[str], message: str, env: dict) -> str:
        args = ["commit-tree", tree_oid]
        for p in parents:
            args.extend(["-p", p])
        msg_bytes = message.encode("utf-8")
        stdout, stderr, code = self._run(args, stdin_bytes=msg_bytes, env=env)
        if code != 0:
            raise GitError(f"Failed commit-tree: {stderr.decode('utf-8', errors='ignore')}")
        return stdout.decode("utf-8").strip()

    def update_ref(self, ref_name: str, new_oid: str, old_oid: Optional[str] = None):
        args = ["update-ref", ref_name, new_oid]
        if old_oid:
            args.append(old_oid)
        stdout, stderr, code = self._run(args)
        if code != 0:
            raise GitError(f"Failed update-ref {ref_name} -> {new_oid} (old={old_oid}): {stderr.decode('utf-8', errors='ignore')}")

    def merge_base_is_ancestor(self, ancestor_oid: str, descendant_oid: str) -> bool:
        stdout, stderr, code = self._run(["merge-base", "--is-ancestor", ancestor_oid, descendant_oid])
        return code == 0

    def diff_tree_raw(self, old_tree: str, new_tree: str) -> List[dict]:
        stdout, stderr, code = self._run(["diff-tree", "-r", "--raw", "-z", "--no-renames", old_tree, new_tree])
        if code != 0:
            raise GitError(f"Failed diff-tree between {old_tree} and {new_tree}: {stderr.decode('utf-8', errors='ignore')}")
        results = []
        raw_chunks = stdout.split(b"\x00")
        i = 0
        while i < len(raw_chunks):
            chunk = raw_chunks[i]
            if not chunk or not chunk.startswith(b":"):
                i += 1
                continue
            meta = chunk.decode("ascii", errors="replace").split()
            # meta: :<old-mode> <new-mode> <old-oid> <new-oid> <status>
            i += 1
            if i < len(raw_chunks):
                path = raw_chunks[i].decode("utf-8", errors="replace")
                results.append({
                    "old_mode": meta[0][1:] if meta[0].startswith(":") else meta[0],
                    "new_mode": meta[1],
                    "old_oid": meta[2],
                    "new_oid": meta[3],
                    "status": meta[4],
                    "path": path
                })
            i += 1
        return results

    def push_ref(self, remote: str, src_ref: str, dst_ref: str, no_follow_tags: bool = True, dry_run: bool = False) -> Tuple[bool, str]:
        refspec = f"{src_ref}:{dst_ref}"
        args = ["push", remote, refspec]
        if no_follow_tags:
            args.append("--no-follow-tags")
        if dry_run:
            args.append("--dry-run")
        stdout, stderr, code = self._run(args)
        out_msg = (stdout + b"\n" + stderr).decode("utf-8", errors="replace").strip()
        return (code == 0), out_msg
