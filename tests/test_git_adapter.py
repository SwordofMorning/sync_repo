import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine.git_adapter import GitAdapter, GitError


class TestGitAdapterV3(unittest.TestCase):
    def setUp(self):
        playground_tmp = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "../../../.playground/sync/tmp_git_adapter_tests")
        )
        os.makedirs(playground_tmp, exist_ok=True)
        self.tmp_dir = tempfile.TemporaryDirectory(dir=playground_tmp)
        self.root = self.tmp_dir.name
        self.remote_dir = os.path.join(self.root, "remote.git")
        self.repo_dir = os.path.join(self.root, "repo")
        self.other_dir = os.path.join(self.root, "other")

        os.makedirs(self.remote_dir)
        os.makedirs(self.repo_dir)

        # Initialize bare remote with HEAD -> refs/heads/main
        self._git_raw(self.remote_dir, ["init", "--bare"])
        self._git_raw(self.remote_dir, ["symbolic-ref", "HEAD", "refs/heads/main"])

        # Initialize primary repo
        self._git_raw(self.repo_dir, ["init"])
        self._git_raw(self.repo_dir, ["config", "user.name", "Test User"])
        self._git_raw(self.repo_dir, ["config", "user.email", "test@example.com"])
        self._git_raw(self.repo_dir, [" checkout", "-b", "main"])
        self._git_raw(self.repo_dir, ["remote", "add", "origin", self.remote_dir])

        self.git = GitAdapter(self.repo_dir)

        # Create initial commit c1
        self._write_worktree_file(self.repo_dir, "README.md", b"# Hello\n")
        self._write_worktree_file(self.repo_dir, "src/main.c", b"int main() { return 0; }\n")
        self._write_worktree_file(self.repo_dir, "src/util.h", b"#pragma once\n")
        self._git_raw(self.repo_dir, ["add", "."])
        self._git_raw(self.repo_dir, ["commit", "-m", "initial commit"])
        self.c1 = self.git.rev_parse("HEAD")
        self.t1 = self.git.rev_parse("HEAD^{tree}")
        self._git_raw(self.repo_dir, ["push", "-u", "origin", "refs/heads/main"])

    def tearDown(self):
        self.tmp_dir.cleanup()

    def _git_raw(self, cwd: str, args: list):
        import subprocess

        clean_args = [a.strip() for a in args]
        proc = subprocess.run(
            ["git", "-C", cwd] + clean_args,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        )
        return proc.stdout

    def _write_worktree_file(self, base: str, rel_path: str, data: bytes):
        full = os.path.join(base, rel_path)
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "wb") as f:
            f.write(data)

    def test_run_checked_raises_git_error_on_nonzero_exit_at2_01(self):
        # Direct failure on nonexistent tree/commit must raise GitError, never empty list
        bad_oid = "deadbeef" * 5
        with self.assertRaises(GitError) as ctx:
            self.git._run_checked(["ls-tree", "-z", bad_oid])
        self.assertIn("exit=", str(ctx.exception))

        with self.assertRaises(GitError):
            self.git.ls_tree_z(bad_oid)

        with self.assertRaises(GitError):
            self.git.ls_tree_r_z_strict(bad_oid)

        with self.assertRaises(GitError):
            self.git.diff_tree_raw_strict(self.t1, bad_oid)

        # Simulate exit=128 with empty stdout via mock to directly verify AT2-01
        with patch.object(self.git, "_run", return_value=(b"", b"fatal: tree corrupted", 128)):
            with self.assertRaises(GitError) as ctx2:
                self.git.ls_tree_z(self.t1)
            self.assertIn("exit=128", str(ctx2.exception))
            self.assertIn("fatal: tree corrupted", str(ctx2.exception))

    def test_strict_utf8_path_rejection_in_ls_tree_and_diff_tree(self):
        # Construct a real tree object in Git with non-UTF-8 filename bytes (0xff 0xfe)
        blob_oid = self.git.hash_object_write(b"content")
        raw_entry = f"100644 blob {blob_oid}\t".encode("ascii") + b"invalid_\xff\xfe.c\x00"
        bad_tree_oid = (
            self.git._run_checked(["mktree", "-z"], stdin_bytes=raw_entry)
            .decode("ascii")
            .strip()
        )

        with self.assertRaises(GitError) as ctx1:
            self.git.ls_tree_z(bad_tree_oid)
        self.assertIn("UTF-8", str(ctx1.exception))

        with self.assertRaises(GitError) as ctx2:
            self.git.ls_tree_r_z_strict(bad_tree_oid)
        self.assertIn("UTF-8", str(ctx2.exception))

        with self.assertRaises(GitError) as ctx3:
            self.git.diff_tree_raw_strict(self.t1, bad_tree_oid)
        self.assertIn("UTF-8", str(ctx3.exception))

    def test_ls_tree_z_and_ls_tree_r_z_strict_and_diff_tree_raw_strict(self):
        # 1. Non-recursive ls_tree_z at root
        root_entries = self.git.ls_tree_z(self.t1)
        by_name = {e["name"]: e for e in root_entries}
        self.assertEqual(set(by_name.keys()), {"README.md", "src"})
        self.assertEqual(by_name["README.md"]["type"], "blob")
        self.assertEqual(by_name["README.md"]["mode"], "100644")
        self.assertEqual(by_name["src"]["type"], "tree")
        self.assertEqual(by_name["src"]["mode"], "040000")

        # 2. Recursive ls_tree_r_z_strict
        rec_entries = self.git.ls_tree_r_z_strict(self.t1)
        by_path = {e["path"]: e for e in rec_entries}
        self.assertEqual(set(by_path.keys()), {"README.md", "src/main.c", "src/util.h"})

        # 3. Create second commit modifying src/main.c, deleting src/util.h, adding src/new.c
        self._write_worktree_file(self.repo_dir, "src/main.c", b"int main() { return 1; }\n")
        os.remove(os.path.join(self.repo_dir, "src/util.h"))
        self._write_worktree_file(self.repo_dir, "src/new.c", b"void helper() {}\n")
        self._git_raw(self.repo_dir, ["add", "-A"])
        self._git_raw(self.repo_dir, ["commit", "-m", "second commit"])
        t2 = self.git.rev_parse("HEAD^{tree}")

        diffs = self.git.diff_tree_raw_strict(self.t1, t2)
        diff_by_path = {d["path"]: d for d in diffs}
        self.assertEqual(set(diff_by_path.keys()), {"src/main.c", "src/util.h", "src/new.c"})
        self.assertEqual(diff_by_path["src/main.c"]["status"], "M")
        self.assertEqual(diff_by_path["src/util.h"]["status"], "D")
        self.assertEqual(diff_by_path["src/new.c"]["status"], "A")

    def test_ls_remote_ref_reachable_missing_and_unreachable(self):
        # Existing ref on reachable remote
        remote_main = self.git.ls_remote_ref("origin", "refs/heads/main")
        self.assertEqual(remote_main, self.c1)

        # Missing ref on reachable remote -> None (exit code 0)
        missing_ref = self.git.ls_remote_ref("origin", "refs/heads/does_not_exist")
        self.assertIsNone(missing_ref)

        # Unreachable/invalid remote -> raises GitError
        with self.assertRaises(GitError):
            self.git.ls_remote_ref("/nonexistent/remote/path.git", "refs/heads/main")

    def test_check_is_ancestor_tri_state_with_missing_remote_objects(self):
        # Clone remote to another directory and push a new commit c2 so self.git doesn't have c2 locally
        self._git_raw(self.root, ["clone", self.remote_dir, self.other_dir])
        other_git = GitAdapter(self.other_dir)
        self._git_raw(self.other_dir, ["config", "user.name", "Other User"])
        self._git_raw(self.other_dir, ["config", "user.email", "other@example.com"])
        self._write_worktree_file(self.other_dir, "README.md", b"# Updated from other\n")
        self._git_raw(self.other_dir, ["add", "README.md"])
        self._git_raw(self.other_dir, ["commit", "-m", "remote advance"])
        c2_remote = other_git.rev_parse("HEAD")
        self._git_raw(self.other_dir, ["push", "origin", "HEAD:refs/heads/main"])

        # Initially self.git does not have c2_remote
        self.assertFalse(self.git.has_object(c2_remote))

        # Without remote_for_missing, must return UNKNOWN (never FALSE)
        self.assertEqual(
            self.git.check_is_ancestor_tri_state(self.c1, c2_remote),
            "UNKNOWN",
        )

        # With remote_for_missing + remote_ref_for_missing, fetches object and returns TRUE
        res = self.git.check_is_ancestor_tri_state(
            self.c1,
            c2_remote,
            remote_for_missing="origin",
            remote_ref_for_missing="refs/heads/main",
        )
        self.assertEqual(res, "TRUE")
        self.assertTrue(self.git.has_object(c2_remote))

        # Reverse order (c2_remote is NOT ancestor of c1) -> FALSE
        self.assertEqual(
            self.git.check_is_ancestor_tri_state(c2_remote, self.c1),
            "FALSE",
        )

        # Non-commit object (blob OID) causes merge-base exit 128 -> UNKNOWN
        blob_oid = self.git.ls_tree_z(self.t1)[0]["oid"]
        self.assertEqual(
            self.git.check_is_ancestor_tri_state(blob_oid, self.c1),
            "UNKNOWN",
        )

        # Still missing object even after fetch -> UNKNOWN
        fake_oid = "12345678" * 5
        self.assertEqual(
            self.git.check_is_ancestor_tri_state(
                self.c1,
                fake_oid,
                remote_for_missing="origin",
                remote_ref_for_missing="refs/heads/main",
            ),
            "UNKNOWN",
        )

    def test_read_tree_and_status_porcelain_z(self):
        # Clean worktree initially
        self.assertEqual(self.git.status_porcelain_z(), [])

        # Dirty worktree with untracked file
        untracked_path = os.path.join(self.repo_dir, "untracked.old")
        with open(untracked_path, "wb") as f:
            f.write(b"dirty")
        status = self.git.status_porcelain_z()
        self.assertTrue(any(b"untracked.old" in entry for entry in status))
        os.remove(untracked_path)
        self.assertEqual(self.git.status_porcelain_z(), [])

        # Build a new tree via plumbing and synchronize index via read_tree
        new_blob = self.git.hash_object_write(b"# Version 2\n")
        root_entries = self.git.ls_tree_z(self.t1)
        records = []
        for e in root_entries:
            if e["name"] == "README.md":
                records.append((e["mode"], e["type"], new_blob, e["name"]))
            else:
                records.append((e["mode"], e["type"], e["oid"], e["name"]))
        new_tree = self.git.mktree_z(records)

        # Write matching file to worktree and read_tree into index
        self._write_worktree_file(self.repo_dir, "README.md", b"# Version 2\n")
        self.git.read_tree(new_tree)
        self.git.update_ref("refs/heads/main", self.git.commit_tree(new_tree, [self.c1], "v2"))
        self.assertEqual(self.git.status_porcelain_z(), [])

    def test_get_remote_url_and_get_symbolic_head(self):
        self.assertEqual(self.git.get_remote_url("origin", push=False), self.remote_dir)
        self.assertEqual(self.git.get_remote_url("origin", push=True), self.remote_dir)
        self.assertEqual(self.git.get_symbolic_head(), "refs/heads/main")

        # Detach HEAD
        self._git_raw(self.repo_dir, ["checkout", "--detach", self.c1])
        self.assertIsNone(self.git.get_symbolic_head())

    def test_push_ref_with_force_with_lease(self):
        # Create a candidate commit on a candidate ref
        new_blob = self.git.hash_object_write(b"# Candidate\n")
        records = [
            (e["mode"], e["type"], new_blob if e["name"] == "README.md" else e["oid"], e["name"])
            for e in self.git.ls_tree_z(self.t1)
        ]
        cand_tree = self.git.mktree_z(records)
        cand_commit = self.git.commit_tree(cand_tree, [self.c1], "candidate commit")
        cand_ref = "refs/sync/candidates/test_tx"
        self.git.update_ref(cand_ref, cand_commit)

        # 1. Stale expected_old_remote_oid must be rejected by --force-with-lease
        stale_oid = "abcd1234" * 5
        ok_stale, msg_stale = self.git.push_ref(
            "origin",
            cand_ref,
            "refs/heads/main",
            expected_old_remote_oid=stale_oid,
        )
        self.assertFalse(ok_stale, f"Expected stale lease push to fail, got: {msg_stale}")
        self.assertEqual(self.git.ls_remote_ref("origin", "refs/heads/main"), self.c1)

        # 2. Matching expected_old_remote_oid succeeds
        ok_valid, msg_valid = self.git.push_ref(
            "origin",
            cand_ref,
            "refs/heads/main",
            expected_old_remote_oid=self.c1,
        )
        self.assertTrue(ok_valid, f"Expected valid lease push to succeed, got: {msg_valid}")
        self.assertEqual(self.git.ls_remote_ref("origin", "refs/heads/main"), cand_commit)

    def test_env_isolation_for_dry_run_plumbing(self):
        ephemeral_obj_dir = os.path.join(self.root, "ephemeral_objects")
        os.makedirs(ephemeral_obj_dir, exist_ok=True)
        dry_env = {
            "GIT_OBJECT_DIRECTORY": ephemeral_obj_dir,
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": os.path.join(self.repo_dir, ".git", "objects"),
        }

        blob_oid = self.git.hash_object_write(b"ephemeral dry-run blob\n", env=dry_env)
        # Must exist with dry_env, must NOT exist in real repository object store
        self.assertTrue(self.git.has_object(blob_oid, env=dry_env))
        self.assertFalse(self.git.has_object(blob_oid))
        self.assertEqual(
            self.git.cat_file_blob(blob_oid, env=dry_env),
            b"ephemeral dry-run blob\n",
        )

        records = [("100644", "blob", blob_oid, "dry.txt")]
        tree_oid = self.git.mktree_z(records, env=dry_env)
        self.assertFalse(self.git.has_object(tree_oid))
        self.assertEqual(len(self.git.ls_tree_r_z_strict(tree_oid, env=dry_env)), 1)

        commit_oid = self.git.commit_tree(tree_oid, [self.c1], "dry-run commit", env=dry_env)
        self.assertTrue(self.git.has_object(commit_oid, env=dry_env))
        self.assertFalse(self.git.has_object(commit_oid))


if __name__ == "__main__":
    unittest.main()
