"""Hermetic contract tests. Real Windows/TSD acceptance still needs win11s."""

import copy
import ctypes
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine.dlp_verifier import DLP_CONTRACT_SPEC_VERSION, DlpVerifier, GateStatus
from engine.git_adapter import GitAdapter
import engine.workspace_materializer as materializer_module
from engine.workspace_materializer import (
    CorruptedCipherBlobError,
    MaterializeError,
    TSD_MAGIC_HEADER,
    WorkspaceMaterializer,
    terminate_lingering_worker,
)


def cipher_fixture(plain):
    payload = TSD_MAGIC_HEADER + len(plain).to_bytes(8, "little") + plain
    size = max(8192, ((len(payload) + 4095) // 4096) * 4096)
    return payload.ljust(size, b"\xa5")


def decrypt_fixture(path, raw):
    if not path.endswith(".old") or not os.path.isfile(path):
        raise AssertionError("The production .old bridge was bypassed")
    with open(path, "rb") as stream:
        if stream.read() != raw:
            raise AssertionError("Staged memory cipher differs from the input")
    offset = len(TSD_MAGIC_HEADER)
    size = int.from_bytes(raw[offset:offset + 8], "little")
    return raw[offset + 8:offset + 8 + size]


class GitFixture(unittest.TestCase):
    def setUp(self):
        scratch = os.path.abspath(os.path.join(
            os.path.dirname(__file__), "../../../.playground/sync/tmp_materializer_dlp_tests"
        ))
        os.makedirs(scratch, exist_ok=True)
        sandbox = tempfile.TemporaryDirectory(dir=scratch)
        self.addCleanup(sandbox.cleanup)
        self.root = sandbox.name
        self.a = self.repo("repo a %PATH% 中文")
        self.b = self.repo("repo b")

    def repo(self, name):
        path = os.path.join(self.root, name)
        subprocess.run(["git", "init", "-q", path], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        git = GitAdapter(path)
        git._run_checked(["config", "user.name", "DLP Test"])
        git._run_checked(["config", "user.email", "dlp@example.org"])
        git._run_checked(["config", "core.autocrlf", "false"])
        git._run_checked(["symbolic-ref", "HEAD", "refs/heads/main"])
        return git

    def write(self, git, path, data):
        absolute = os.path.join(git.repo_dir, *path.split("/"))
        os.makedirs(os.path.dirname(absolute), exist_ok=True)
        with open(absolute, "wb") as stream:
            stream.write(data)
        return absolute

    @staticmethod
    def read(path):
        with open(path, "rb") as stream:
            return stream.read()

    def tree(self, git, files):
        root = {}
        for path, value in files.items():
            mode, data = value if isinstance(value, tuple) else ("100644", value)
            node = root
            parts = path.split("/")
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            node[parts[-1]] = (mode, "blob", git.hash_object_write(data))

        def build(node):
            return git.mktree_z([
                ("040000", "tree", build(value), name) if isinstance(value, dict)
                else (*value, name) for name, value in node.items()
            ])
        return build(root)

    def baseline(self, git, files):
        tree = self.tree(git, files)
        commit = git.commit_tree(tree, [], "baseline")
        git.update_ref("refs/heads/main", commit)
        git._run_checked(["reset", "--hard", commit])
        self.assertEqual([], git.status_porcelain_z())
        return tree

    def materializer(self, git=None, **kwargs):
        git = git or self.a
        worker = WorkspaceMaterializer(git, git.repo_dir, **kwargs)
        worker.lock_backoff = []
        return worker


class TestStagingAndMaterialization(GitFixture):
    def test_at08a_tracked_old_collision_and_durable_isolated_manifest(self):
        old = self.baseline(self.a, {"component/foo.c": b"old c\n", "component/foo.c.old": b"old old\n"})
        new = self.tree(self.a, {"component/foo.c": b"new c\n", "component/foo.c.old": b"new old\n"})
        worker = self.materializer(direction="B2A", tx_id="collision")
        with patch.object(materializer_module.os, "fsync", wraps=os.fsync) as fsync:
            info = worker.prepare_transaction_staging(old, new)
        self.assertGreaterEqual(fsync.call_count, 5)
        self.assertEqual(b"old c\n", self.read(os.path.join(self.a.repo_dir, "component/foo.c")))
        self.assertEqual(b"old old\n", self.read(os.path.join(self.a.repo_dir, "component/foo.c.old")))
        self.assertEqual(hashlib.sha256(self.read(info["manifest_path"])).hexdigest(), info["manifest_sha256"])
        self.assertEqual(2, len(info["worktree_journal"]))
        for entry in info["worktree_journal"]:
            self.assertTrue(entry["stage_old_path"].startswith(os.path.join(worker.staging_dir, "staged")))
            self.assertTrue(entry["backup_path"].startswith(os.path.join(worker.staging_dir, "rollback")))
            self.assertTrue(entry["stage_old_path"].endswith(".old"))
            self.assertTrue(entry["backup_path"].endswith(".bak"))
        summary = worker.materialize_delta_unencrypted_via_old(old, new, info)
        self.assertEqual({"added": 0, "modified": 2, "deleted": 0, "type_changed": 0}, summary)
        self.assertEqual(b"new c\n", self.read(os.path.join(self.a.repo_dir, "component/foo.c")))
        self.assertEqual(b"new old\n", self.read(os.path.join(self.a.repo_dir, "component/foo.c.old")))

    def test_at08b_untracked_or_modified_worktree_is_not_touched(self):
        old = self.baseline(self.a, {"foo.c": b"old\n"})
        new = self.tree(self.a, {"foo.c": b"new\n"})
        sentinel = self.write(self.a, "untracked.old", b"preserve me\n")
        worker = self.materializer(direction="B2A")
        with self.assertRaisesRegex(MaterializeError, "dirty|untracked"):
            worker.materialize_delta(old, new)
        self.assertFalse(os.path.exists(worker.staging_dir))
        self.assertEqual(b"preserve me\n", self.read(sentinel))
        os.remove(sentinel)
        self.write(self.a, "foo.c", b"local edits\n")
        with self.assertRaises(MaterializeError):
            worker.prepare_transaction_staging(old, new)
        info = worker.prepare_transaction_staging(old, new, allow_dirty=True)
        self.assertEqual(b"local edits\n", self.read(info["worktree_journal"][0]["backup_path"]))
        self.assertEqual(b"local edits\n", self.read(os.path.join(self.a.repo_dir, "foo.c")))

    def test_at09_percent_unicode_spaces_and_type_mode_changes(self):
        old = self.baseline(self.a, {"目录 空格/%PATH% 引号'.c": b"before\n", "remove.c": b"gone\n"})
        new_files = {"目录 空格/%PATH% 引号'.c": ("100755", b"after\n"),
                     "新 文件.c": b"added\n"}
        new = self.tree(self.a, new_files)
        worker = self.materializer(direction="B2A")
        summary = worker.materialize_delta(old, new)
        self.assertEqual(1, summary["added"])
        self.assertEqual(1, summary["modified"])
        self.assertEqual(1, summary["deleted"])
        self.assertEqual(b"after\n", self.read(os.path.join(self.a.repo_dir, "目录 空格/%PATH% 引号'.c")))
        self.assertFalse(os.path.lexists(os.path.join(self.a.repo_dir, "remove.c")))
        self.assertEqual([], [name for name in os.listdir(self.a.repo_dir) if name.startswith(".sync_canary")])

    def test_at09_mid_batch_physical_failure_stops_and_rolls_back_b2a(self):
        files = {"a %PATH%.c": b"old a\n", "b 中文.c": b"old b\n",
                 "delete.c": b"restore deleted\n", "z untouched.c": b"old z\n"}
        old = self.baseline(self.a, files)
        new = self.tree(self.a, {"a %PATH%.c": b"new a\n", "b 中文.c": b"new b\n",
                                 "new.c": b"new addition\n", "z untouched.c": b"new z\n"})
        worker = self.materializer(direction="B2A")
        info = worker.prepare_transaction_staging(old, new)
        calls = []

        def runner(manifest):
            calls.append(manifest)
            if len(calls) == 1:
                failed = next(item for item in manifest["items"] if item.get("path") == "b 中文.c")
                with open(failed["stage_old_path"], "wb") as stream:
                    stream.write(b"tampered staging")
            return worker._run_posix_manifest(manifest)

        worker.unmonitored_runner = runner
        with self.assertRaisesRegex(MaterializeError, "worker failed"):
            worker.materialize_delta_unencrypted_via_old(old, new, info)
        self.assertEqual(b"new a\n", self.read(os.path.join(self.a.repo_dir, "a %PATH%.c")))
        self.assertEqual(b"old z\n", self.read(os.path.join(self.a.repo_dir, "z untouched.c")))
        self.assertFalse(os.path.exists(os.path.join(self.a.repo_dir, "new.c")))
        worker.rollback_from_journal(info["worktree_journal"], "B2A")
        worker.rollback_from_journal(info["worktree_journal"], "B2A")  # retryable .bak evidence
        for path, data in files.items():
            self.assertEqual(data, self.read(os.path.join(self.a.repo_dir, path)))
        self.assertEqual([], self.a.status_porcelain_z())

    def test_final_retry_always_performs_double_in_place_rewrite(self):
        worker = self.materializer()
        worker.lock_backoff = [0, 0]
        target = os.path.join(self.a.repo_dir, "retry.c")
        original_open = open
        failures, successful_modes = [2], []

        def flaky_open(path, mode="r", *args, **kwargs):
            if path == target:
                if failures[0]:
                    failures[0] -= 1
                    raise PermissionError("DLP/file lock")
                successful_modes.append(mode)
            return original_open(path, mode, *args, **kwargs)

        with patch("builtins.open", side_effect=flaky_open), patch.object(
            materializer_module.os, "fsync", wraps=os.fsync
        ) as fsync:
            worker._safe_write_bytes(target, b"final attempt\n")
        self.assertEqual(["wb", "rb", "wb"], successful_modes)
        self.assertEqual(2, fsync.call_count)
        self.assertEqual(b"final attempt\n", self.read(target))

    def test_two_argument_a2b_api_and_deletions_precede_writes(self):
        old = self.baseline(self.b, {"delete.c": b"gone", "modify.c": b"before"})
        new = self.tree(self.b, {"modify.c": b"after", "added.c": b"new"})
        worker = WorkspaceMaterializer(self.b, self.b.repo_dir)
        worker.lock_backoff = []
        events = []
        remove, write = worker._safe_remove_file, worker._safe_write_bytes

        def record_remove(path):
            events.append("delete")
            return remove(path)

        def record_write(path, data, is_symlink=False):
            events.append("write")
            return write(path, data, is_symlink)

        with patch.object(worker, "_safe_remove_file", side_effect=record_remove), patch.object(
            worker, "_safe_write_bytes", side_effect=record_write
        ):
            summary = worker.materialize_delta(old, new)
        self.assertEqual("delete", events[0])
        self.assertEqual({"added": 1, "modified": 1, "deleted": 1, "type_changed": 0}, summary)
        self.assertEqual(b"after", self.read(os.path.join(self.b.repo_dir, "modify.c")))

    def test_paths_and_reparse_points_rejected_before_deletion(self):
        old = self.baseline(self.a, {"delete.c": b"keep"})
        new = self.tree(self.a, {"link/file.c": b"new"})
        outside = os.path.join(self.root, "outside")
        os.makedirs(outside)
        os.symlink(outside, os.path.join(self.a.repo_dir, "link"))
        worker = self.materializer()
        with self.assertRaisesRegex(MaterializeError, "Reparse|symlink"):
            worker.materialize_delta(old, new)
        self.assertEqual(b"keep", self.read(os.path.join(self.a.repo_dir, "delete.c")))
        self.assertEqual([], os.listdir(outside))
        with self.assertRaises(MaterializeError):
            worker._target_path("../outside/evil.c")
        with self.assertRaises(MaterializeError):
            worker._target_path(".git/config")

    def test_at211_preparing_failure_never_changes_worktree(self):
        files = {"a.c": b"old a", "b.c": b"old b"}
        old = self.baseline(self.a, files)
        new = self.tree(self.a, {"a.c": b"new a", "b.c": b"new b"})
        worker = self.materializer(tx_id="preparing")
        original_write = materializer_module._write_fsynced

        def interrupt_second_backup(path, data):
            if path.endswith(".bak") and os.path.basename(path).startswith("1_"):
                raise OSError("crash while preparing backups")
            return original_write(path, data)

        with patch.object(materializer_module, "_write_fsynced", side_effect=interrupt_second_backup):
            with self.assertRaisesRegex(OSError, "preparing"):
                worker.prepare_transaction_staging(old, new)
        self.assertIsNone(worker.last_staging_info)
        self.assertFalse(os.path.exists(os.path.join(worker.staging_dir, "manifest.json")))
        for path, data in files.items():
            self.assertEqual(data, self.read(os.path.join(self.a.repo_dir, path)))
        self.assertEqual([], self.a.status_porcelain_z())
        prepared = self.materializer(tx_id="prepared").prepare_transaction_staging(old, new)
        self.assertTrue(os.path.isfile(prepared["manifest_path"]))
        self.assertEqual(2, len(prepared["worktree_journal"]))
        self.assertEqual([], self.a.status_porcelain_z())

    def test_at211_a2b_rollback_uses_encryption_triggering_double_write(self):
        files = {"a.c": b"old a", "deleted.c": b"old deleted"}
        old = self.baseline(self.b, files)
        new = self.tree(self.b, {"a.c": b"new a", "added.c": b"new added"})
        worker = self.materializer(self.b, tx_id="encrypted-rollback")
        info = worker.prepare_transaction_staging(old, new)
        worker.materialize_delta(old, new)
        original_write = worker._safe_write_bytes
        rewrite_calls = []

        def dlp_driver_write(path, data, is_symlink=False):
            rewrite_calls.append((path, is_symlink))
            original_write(path, data, is_symlink=is_symlink)
            with open(path, "wb") as stream:
                stream.write(cipher_fixture(data))

        with patch.object(worker, "_safe_write_bytes", side_effect=dlp_driver_write):
            worker.rollback_from_journal(info["worktree_journal"], direction="A2B")
        self.assertEqual(2, len(rewrite_calls))
        self.assertTrue(all(is_symlink is False for _, is_symlink in rewrite_calls))
        for path, data in files.items():
            raw = self.read(os.path.join(self.b.repo_dir, path))
            self.assertTrue(raw.startswith(TSD_MAGIC_HEADER))
            self.assertEqual(data, raw[len(TSD_MAGIC_HEADER) + 8:len(TSD_MAGIC_HEADER) + 8 + len(data)])
        self.assertFalse(os.path.exists(os.path.join(self.b.repo_dir, "added.c")))

    def test_backup_and_manifest_tampering_fail_closed(self):
        old = self.baseline(self.a, {"a.c": b"old"})
        new = self.tree(self.a, {"a.c": b"new"})
        worker = self.materializer(direction="B2A")
        info = worker.prepare_transaction_staging(old, new)
        with open(info["manifest_path"], "ab") as stream:
            stream.write(b" ")
        with self.assertRaisesRegex(MaterializeError, "manifest SHA"):
            worker.materialize_delta_unencrypted_via_old(old, new, info)
        with open(info["worktree_journal"][0]["backup_path"], "wb") as stream:
            stream.write(b"corrupt")
        with self.assertRaisesRegex(MaterializeError, "backup size"):
            worker.rollback_from_journal(info["worktree_journal"])
        self.assertEqual(b"old", self.read(os.path.join(self.a.repo_dir, "a.c")))

    def test_worker_result_must_bind_transaction_nonce_and_every_item(self):
        old = self.baseline(self.a, {"a.c": b"old"})
        new = self.tree(self.a, {"a.c": b"new"})
        worker = self.materializer(direction="B2A")
        info = worker.prepare_transaction_staging(old, new)
        for response in ({"tx_id": "other", "nonce": info["nonce"], "overall_status": "PASS", "items": []},
                         {"tx_id": worker.tx_id, "nonce": info["nonce"], "overall_status": "PASS", "items": []}):
            worker.unmonitored_runner = Mock(return_value=response)
            with self.assertRaises(MaterializeError):
                worker.materialize_delta_unencrypted_via_old(old, new, info)
        self.assertEqual(b"old", self.read(os.path.join(self.a.repo_dir, "a.c")))


class TestWorkerLeaseAndTermination(GitFixture):
    @staticmethod
    def kernel(creation):
        kernel = Mock()
        kernel.OpenProcess.return_value = 0x123456
        kernel.TerminateProcess.return_value = True
        kernel.WaitForSingleObject.side_effect = [258, 0]

        def times(handle, created, exited, system, user):
            created._obj.low = creation & 0xffffffff
            created._obj.high = creation >> 32
            return 1

        kernel.GetProcessTimes.side_effect = times
        return kernel

    def test_at210_pid_reuse_closes_handle_without_terminating(self):
        kernel = self.kernel(0x123456789ab)
        lease = {"worker_pid": 8181, "worker_create_time_ft": 0x11111111111}
        with patch.object(materializer_module, "_IS_WINDOWS", True), patch.object(
            materializer_module, "_windows_kernel32", return_value=kernel
        ):
            result = terminate_lingering_worker(lease)
        self.assertEqual("pid_reused_skipped", result)
        kernel.TerminateProcess.assert_not_called()
        kernel.WaitForSingleObject.assert_not_called()
        kernel.CloseHandle.assert_called_once_with(0x123456)
        self.assertEqual(0x123456, kernel.GetProcessTimes.call_args[0][0])

    def test_at210_termination_checks_and_kills_the_same_handle(self):
        creation = 0x1ffabcdef12
        kernel = self.kernel(creation)
        with patch.object(materializer_module, "_IS_WINDOWS", True), patch.object(
            materializer_module, "_windows_kernel32", return_value=kernel
        ):
            self.assertEqual("terminated", terminate_lingering_worker(
                {"worker_pid": 9191, "worker_create_time_ft": creation}
            ))
        kernel.TerminateProcess.assert_called_once_with(0x123456, 137)
        self.assertEqual(0x123456, kernel.GetProcessTimes.call_args[0][0])
        self.assertEqual(0x123456, kernel.WaitForSingleObject.call_args[0][0])
        kernel.CloseHandle.assert_called_once_with(0x123456)
        self.assertEqual("not_registered", terminate_lingering_worker({"worker_pid": None}))

    def test_at210_prespawn_intent_is_durable_before_runner(self):
        old = self.baseline(self.a, {"a.c": b"old"})
        new = self.tree(self.a, {"a.c": b"new"})
        worker = self.materializer(direction="B2A")
        info = worker.prepare_transaction_staging(old, new)
        events = []

        def callback(lease):
            self.assertEqual("SPAWNING", lease["state"])
            self.assertIsNone(lease["worker_pid"])
            with open(lease["lease_file"], encoding="utf-8") as stream:
                self.assertEqual(lease, json.load(stream))
            self.assertFalse(os.path.exists(lease["release_flag_file"]))
            events.append("intent durable")

        def runner(manifest):
            self.assertEqual(["intent durable"], events)
            events.append("spawn")
            return worker._run_posix_manifest(manifest)

        worker.unmonitored_runner = runner
        worker.materialize_delta_unencrypted_via_old(old, new, info, lease_callback=callback)
        self.assertEqual(["intent durable", "spawn"], events)

    def test_at210_crash_before_spawn_never_releases_or_runs_worker(self):
        old = self.baseline(self.a, {"a.c": b"old"})
        new = self.tree(self.a, {"a.c": b"new"})
        worker = self.materializer(direction="B2A", unmonitored_runner=Mock())
        info = worker.prepare_transaction_staging(old, new)
        observed = []

        def interrupted_wal(lease):
            observed.append(lease)
            self.assertTrue(os.path.isfile(lease["lease_file"]))
            raise RuntimeError("crash before Create returns")

        with self.assertRaisesRegex(RuntimeError, "before Create"):
            worker.materialize_delta_unencrypted_via_old(old, new, info, interrupted_wal)
        worker.unmonitored_runner.assert_not_called()
        self.assertFalse(os.path.exists(observed[0]["release_flag_file"]))
        self.assertFalse(os.path.exists(observed[0]["lease_file"]))
        self.assertEqual(b"old", self.read(os.path.join(self.a.repo_dir, "a.c")))

    def test_at210_active_lease_wal_failure_withholds_release_and_fences_handle(self):
        old = self.baseline(self.a, {"a.c": b"old"})
        new = self.tree(self.a, {"a.c": b"new"})
        worker = self.materializer(direction="B2A")
        info = worker.prepare_transaction_staging(old, new)
        leases = []

        def callback(lease):
            leases.append(lease)
            self.assertFalse(os.path.exists(lease["release_flag_file"]))
            if lease["state"] == "ACTIVE":
                raise RuntimeError("WAL fsync failed")

        def spawn(command):
            lease_path = command[command.index("-LeaseFile") + 1]
            with open(lease_path + ".worker", "w", encoding="utf-8") as stream:
                json.dump({"worker_pid": 1234, "worker_create_time_ft": 987654}, stream)
            return 1234

        with patch.object(materializer_module, "_IS_WINDOWS", True), patch.object(
            materializer_module, "get_current_proc_filetime", return_value=456789
        ), patch.object(worker, "_spawn_windows_worker", side_effect=spawn), patch.object(
            materializer_module, "terminate_lingering_worker", return_value="terminated"
        ) as terminate:
            with self.assertRaisesRegex(RuntimeError, "WAL fsync"):
                worker.materialize_delta_unencrypted_via_old(old, new, info, callback)
        self.assertEqual(["SPAWNING", "ACTIVE"], [lease["state"] for lease in leases])
        self.assertFalse(os.path.exists(leases[-1]["release_flag_file"]))
        terminate.assert_called_once()
        self.assertEqual(987654, terminate.call_args[0][0]["worker_create_time_ft"])
        self.assertEqual(b"old", self.read(os.path.join(self.a.repo_dir, "a.c")))

    def test_worker_script_contract_parent_guard_and_literal_json_paths(self):
        script = os.path.join(os.path.dirname(__file__), "../scripts/file_ops_worker.ps1")
        text = self.read(script).decode("utf-8")
        for parameter in ("ManifestPath", "ResultPath", "ParentPid", "ParentCreateTimeFt",
                          "LeaseFile", "ReleaseFlagFile"):
            self.assertIn("$" + parameter, text)
        self.assertLess(text.index("::GetProcessById($ParentPid)"), text.index("Get-Content -LiteralPath"))
        self.assertIn("$null = $parentProc.Handle", text)
        self.assertIn("$parentProc.StartTime.ToFileTimeUtc() -ne $ParentCreateTimeFt", text)
        self.assertIn("AddSeconds(10)", text)
        self.assertIn("exit 99", text)
        self.assertIn("$LeaseFile + '.worker'", text)
        self.assertIn("Assert-ParentAlive", text)
        self.assertNotIn("Invoke-Expression", text)
        self.assertIn("'REPLACE_UNENCRYPTED'", text)
        self.assertIn("'DELETE_FILE'", text)
        self.assertIn("'PROBE_PHYSICAL_HEADER'", text)
        self.assertIn("$ResultPath + '.tmp'", text)
        self.assertIn("[System.IO.File]::ReadAllBytes", text)


class TestCipherBridgeAndCanaries(GitFixture):
    def test_at212_memory_cipher_uses_fsynced_old_and_removes_temporary_file(self):
        plain = b"production-equivalent canary vector\n"
        cipher = cipher_fixture(plain)
        paths = []

        def decrypt(path, raw):
            paths.append(path)
            self.assertTrue(path.startswith(worker.staging_dir))
            return decrypt_fixture(path, raw)

        worker = self.materializer(decrypt_read_hook=decrypt)
        oid = self.a.hash_object_write(cipher)
        with patch.object(materializer_module.os, "fsync", wraps=os.fsync) as fsync:
            self.assertEqual(plain, worker.decrypt_blob_via_old_channel(cipher, oid, "canary.c"))
        self.assertGreaterEqual(fsync.call_count, 1)
        self.assertEqual(1, len(paths))
        self.assertFalse(os.path.exists(paths[0]))
        self.assertEqual(b"plain", worker.decrypt_blob_via_old_channel(b"plain"))
        self.assertEqual(b"", worker.decrypt_blob_via_old_channel(b""))

    def test_at212_corrupt_truncated_unchanged_empty_and_wrong_source_oid_rejected(self):
        cipher = cipher_fixture(b"valid plain")
        hook = Mock(side_effect=decrypt_fixture)
        worker = self.materializer(decrypt_read_hook=hook)
        for raw in (TSD_MAGIC_HEADER + b"\0" * 64, cipher[:-1], cipher[:4096], cipher + b"x"):
            with self.subTest(size=len(raw)), self.assertRaises(CorruptedCipherBlobError):
                worker.decrypt_blob_via_old_channel(raw)
        hook.assert_not_called()
        with self.assertRaisesRegex(CorruptedCipherBlobError, "OID"):
            worker.decrypt_blob_via_old_channel(cipher, "0" * 40)
        for decrypted in (cipher, TSD_MAGIC_HEADER + b"bad", b"", None):
            worker.decrypt_read_hook = Mock(return_value=decrypted)
            with self.assertRaises(CorruptedCipherBlobError):
                worker.decrypt_blob_via_old_channel(cipher)
            self.assertEqual([], [name for name in os.listdir(worker.staging_dir) if name.startswith("dec_")])
        worker.decrypt_read_hook = Mock(side_effect=OSError("driver failure"))
        with self.assertRaisesRegex(CorruptedCipherBlobError, "driver failure"):
            worker.decrypt_blob_via_old_channel(cipher)
        self.assertEqual([], [name for name in os.listdir(worker.staging_dir) if name.startswith("dec_")])

    def test_at213_p1_p2_p3_p4_use_actual_target_cross_directory_replacement(self):
        worker = self.materializer(direction="B2A", decrypt_read_hook=decrypt_fixture)
        manifests = []

        def runner(manifest):
            manifests.append(copy.deepcopy(manifest))
            item = manifest["items"][0]
            self.assertEqual(self.a.repo_dir, os.path.dirname(item["target_abs_path"]))
            self.assertTrue(item["stage_old_path"].startswith(worker.staging_dir))
            self.assertNotEqual(os.path.dirname(item["stage_old_path"]), os.path.dirname(item["target_abs_path"]))
            self.assertEqual(b"existing-canary-target\n", self.read(item["target_abs_path"]))
            return worker._run_posix_manifest(manifest)

        worker.unmonitored_runner = runner
        verifier = DlpVerifier(self.a, self.a.repo_dir, physical_reader=self.read)
        status, reason, report = verifier.run_preflight_canary_probes(
            self.a.repo_dir, self.b.repo_dir, worker, encrypt_write_hook=cipher_fixture
        )
        self.assertEqual(GateStatus.PASS, status, reason)
        self.assertEqual({"P1", "P2", "P3", "P4"}, set(report["probes"]))
        self.assertEqual(3, report["probes"]["P3"]["rejected_vectors"])
        self.assertEqual(1, len(manifests))
        self.assertEqual("3.0", DLP_CONTRACT_SPEC_VERSION)
        self.assertEqual("3.0", report["observer"]["contract_spec_version"])
        self.assertEqual([], report["cleanup_errors"])
        self.assertFalse(os.path.exists(report["probes"]["P4"]["target_abs_path"]))
        for git in (self.a, self.b):
            self.assertFalse(any(name.startswith(".sync_canary") for name in os.listdir(git.repo_dir)))

    def test_at213_p1_transparent_observer_returns_unknown_and_does_not_run_p4(self):
        worker = self.materializer(direction="B2A", decrypt_read_hook=Mock())
        runner = Mock()
        worker.unmonitored_runner = runner

        def transparent_reader(path):
            raw = self.read(path)
            offset = len(TSD_MAGIC_HEADER)
            size = int.from_bytes(raw[offset:offset + 8], "little")
            return raw[offset + 8:offset + 8 + size]

        verifier = DlpVerifier(self.a, self.a.repo_dir, physical_reader=transparent_reader)
        status, reason, report = verifier.run_preflight_canary_probes(
            self.a.repo_dir, self.b.repo_dir, worker, cipher_fixture
        )
        self.assertEqual(GateStatus.UNKNOWN, status)
        self.assertEqual("OBSERVER_TRANSPARENT_DECRYPTION", reason)
        self.assertEqual({"P1"}, set(report["probes"]))
        worker.decrypt_read_hook.assert_not_called()
        runner.assert_not_called()

    def test_at212_p2_is_bound_to_known_plaintext_not_self_hash(self):
        worker = self.materializer(direction="B2A", decrypt_read_hook=lambda path, raw: b"wrong plaintext")
        verifier = DlpVerifier(self.a, self.a.repo_dir, physical_reader=self.read)
        status, reason, report = verifier.run_preflight_canary_probes(
            self.a.repo_dir, self.b.repo_dir, worker, cipher_fixture
        )
        self.assertEqual(GateStatus.FAIL, status)
        self.assertIn("independently known", reason)
        self.assertEqual(GateStatus.FAIL, report["probes"]["P2"]["status"])
        self.assertNotIn("P4", report["probes"])

    def test_at213_p4_physical_encrypted_target_is_rejected(self):
        worker = self.materializer(direction="B2A", decrypt_read_hook=decrypt_fixture)

        def faulty_reader(path):
            raw = self.read(path)
            if os.path.basename(path).startswith(".sync_canary_target_"):
                return cipher_fixture(raw)
            return raw

        verifier = DlpVerifier(self.a, self.a.repo_dir, physical_reader=faulty_reader)
        status, reason, report = verifier.run_preflight_canary_probes(
            self.a.repo_dir, self.b.repo_dir, worker, cipher_fixture
        )
        self.assertEqual(GateStatus.FAIL, status)
        self.assertIn("P4 real target", reason)
        self.assertEqual(GateStatus.FAIL, report["probes"]["P4"]["status"])


class TestLogicalAndPhysicalGates(GitFixture):
    def test_at10_logical_text_equivalence_but_binary_identity(self):
        old = self.baseline(self.a, {"source.c": b"A\nB\n", "firmware.bin": b"\0A\r\nB"})
        self.write(self.a, "source.c", b"A\r\r\nB\r\n")
        verifier = DlpVerifier(self.a, self.a.repo_dir)
        passed, message = verifier.verify_logical_integrity(old, sample_limit=0)
        self.assertTrue(passed, message)
        self.assertIn("2 files", message)
        self.write(self.a, "firmware.bin", b"\0A\nB")
        passed, message = verifier.verify_logical_integrity(old)
        self.assertFalse(passed)
        self.assertIn("Logical hash mismatch", message)

    def test_at10_physical_verifier_never_accepts_missing_tsd_header(self):
        tree = self.baseline(self.b, {"a.c": b"source plaintext"})
        verifier = DlpVerifier(self.b, self.b.repo_dir)
        passed, reason = verifier.verify_physical_dlp_headers(sample_limit=0)
        self.assertFalse(passed)
        self.assertIn("missing/invalid", reason)
        verifier.physical_reader = lambda path: cipher_fixture(self.read(path))
        passed, reason = verifier.verify_physical_dlp_headers(sample_limit=0)
        self.assertTrue(passed, reason)
        self.assertIn("checked=1", reason)
        self.assertEqual(tree, self.b.rev_parse("HEAD^{tree}"))

    def test_at214_full_baseline_finds_historical_unencrypted_file_outside_delta(self):
        old = self.baseline(self.b, {"a_changed.c": b"old\n", "z_historical.c": b"missed clone\n"})
        new = self.tree(self.b, {"a_changed.c": b"new\n", "z_historical.c": b"missed clone\n"})
        self.write(self.b, "a_changed.c", b"new\n")
        observed = []

        def reader(path):
            observed.append(os.path.basename(path))
            data = self.read(path)
            return data if path.endswith("z_historical.c") else cipher_fixture(data)

        verifier = DlpVerifier(self.b, self.b.repo_dir, reader)
        status, reason, report = verifier.verify_transaction_delta_gates("A2B", old, new)
        self.assertEqual(GateStatus.PASS, status, reason)
        self.assertEqual(1, report["checked"])
        status, reason, report = verifier.verify_full_worktree_physical_baseline(new, "B")
        self.assertEqual(GateStatus.FAIL, status)
        self.assertIn("z_historical.c", reason)
        self.assertIn("z_historical.c", observed)
        verifier.physical_reader = lambda path: cipher_fixture(self.read(path))
        status, reason, report = verifier.verify_full_worktree_physical_baseline(new, "Repo_B")
        self.assertEqual(GateStatus.PASS, status, reason)
        self.assertEqual(2, report["checked"])

    def test_at214_repo_a_full_baseline_checks_all_tracked_physical_hashes(self):
        tree = self.baseline(self.a, {"a.c": b"first\n", "z.txt": b"second\n", "empty.c": b""})
        observed = []

        def reader(path):
            observed.append(path)
            return self.read(path)

        verifier = DlpVerifier(self.a, self.a.repo_dir, reader)
        status, reason, report = verifier.verify_full_worktree_physical_baseline(tree, "A")
        self.assertEqual(GateStatus.PASS, status, reason)
        self.assertEqual(3, report["checked"])
        self.assertEqual(3, len(observed))
        verifier.physical_reader = lambda path: cipher_fixture(self.read(path)) if path.endswith("z.txt") else self.read(path)
        status, reason, report = verifier.verify_full_worktree_physical_baseline(tree, "A")
        self.assertEqual(GateStatus.FAIL, status)
        self.assertIn("z.txt", reason)

    def test_at14_at214_pure_delete_absence_and_empty_delta_vacuous_pass(self):
        old = self.baseline(self.a, {"delete.c": b"old", "keep.c": b"keep"})
        new = self.tree(self.a, {"keep.c": b"keep"})
        reader = Mock(side_effect=AssertionError("Pure delete should not read written files"))
        verifier = DlpVerifier(self.a, self.a.repo_dir, reader)
        status, reason, report = verifier.verify_transaction_delta_gates("B2A", old, new)
        self.assertEqual(GateStatus.FAIL, status)
        self.assertIn("still physically exists", reason)
        os.remove(os.path.join(self.a.repo_dir, "delete.c"))
        for direction in ("B2A", "A2B"):
            status, reason, report = verifier.verify_transaction_delta_gates(direction, old, new)
            self.assertEqual(GateStatus.PASS, status, reason)
            self.assertEqual("VACUOUS_PASS_NO_WRITTEN_FILES", reason)
            self.assertEqual(1, report["deleted"])
            status, reason, report = verifier.verify_transaction_delta_gates(direction, new, new)
            self.assertEqual(GateStatus.PASS, status, reason)
            self.assertEqual("VACUOUS_PASS_NO_WRITTEN_FILES", reason)
            self.assertEqual(0, report["checked"])
        reader.assert_not_called()
        for pair in ((old, new), (new, new)):
            status, reason, _ = verifier.verify_transaction_delta_gates("B2A", *pair, observer_healthy=False)
            self.assertEqual(GateStatus.UNKNOWN, status)
            self.assertEqual("PHYSICAL_OBSERVER_UNHEALTHY", reason)

    def test_at214_delta_checks_every_add_modify_type_change_and_delete(self):
        old_files = {"delete.c": b"gone", "modify.c": b"before", "type.c": b"mode"}
        old = self.baseline(self.a, old_files)
        new_files = {"added.c": b"new", "modify.c": b"after", "type.c": ("100755", b"mode")}
        new = self.tree(self.a, new_files)
        worker = self.materializer(direction="B2A")
        worker.materialize_delta(old, new)
        observed = []

        def reader(path):
            observed.append(os.path.basename(path))
            return self.read(path)

        verifier = DlpVerifier(self.a, self.a.repo_dir, reader)
        status, reason, report = verifier.verify_transaction_delta_gates("B2A", old, new)
        self.assertEqual(GateStatus.PASS, status, reason)
        self.assertEqual(4, report["checked"])
        self.assertEqual(3, report["written"])
        self.assertEqual({"added.c", "modify.c", "type.c"}, set(observed))
        verifier.physical_reader = lambda path: b"corrupt" if path.endswith("type.c") else self.read(path)
        status, reason, _ = verifier.verify_transaction_delta_gates("B2A", old, new)
        self.assertEqual(GateStatus.FAIL, status)
        self.assertIn("type.c", reason)

    def test_observer_errors_and_unhealthy_baselines_are_unknown(self):
        old = self.baseline(self.a, {"a.c": b"old"})
        new = self.tree(self.a, {"a.c": b"new"})
        self.write(self.a, "a.c", b"new")
        verifier = DlpVerifier(self.a, self.a.repo_dir, Mock(side_effect=OSError("observer offline")))
        status, reason, _ = verifier.verify_transaction_delta_gates("B2A", old, new)
        self.assertEqual(GateStatus.UNKNOWN, status)
        self.assertIn("observer offline", reason)
        status, _, _ = verifier.verify_full_worktree_physical_baseline(new, "A", observer_healthy=False)
        self.assertEqual(GateStatus.UNKNOWN, status)

    def test_empty_and_non_encrypted_extension_files_need_no_cipher_header(self):
        tree = self.baseline(self.b, {"empty.c": b"", "firmware.bin": b"\0binary", "source.C": b"code"})
        verifier = DlpVerifier(self.b, self.b.repo_dir, self.read)
        status, reason, report = verifier.verify_full_worktree_physical_baseline(tree, "B", [])
        self.assertEqual(GateStatus.PASS, status, reason)
        self.assertEqual(3, report["checked"])
        status, reason, _ = verifier.verify_full_worktree_physical_baseline(tree, "B", ["c"])
        self.assertEqual(GateStatus.FAIL, status)
        self.assertIn("source.C", reason)


if __name__ == "__main__":
    unittest.main()
