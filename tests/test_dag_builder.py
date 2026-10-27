import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, call, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine.dag_builder import (
    BidirectionalDAGPlanner,
    ConcurrentDivergenceError,
    DAGBuilder,
    DAGEngineError,
    HistoryRewrittenError,
    NonLinearHistoryError,
)
from engine.git_adapter import GitAdapter
from engine.process_lock import LockBusyError, ProcessLock, generate_tx_id


class _TemporaryWorkspace(unittest.TestCase):
    def setUp(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        workspace = repo_root
        while not os.path.isdir(os.path.join(workspace, ".playground")):
            parent = os.path.dirname(workspace)
            if parent == workspace:
                workspace = repo_root  # Standalone checkouts need no external fixture paths.
                break
            workspace = parent
        playground = os.path.join(workspace, ".playground", "sync")
        os.makedirs(playground, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="dag_lock_tests_", dir=playground)
        self.addCleanup(self.temporary.cleanup)
        self.root = self.temporary.name


class _GitRepositories(_TemporaryWorkspace):
    def setUp(self):
        super().setUp()
        self.source_git = self._init_repo("repo_a")
        self.target_git = self._init_repo("repo_b")
        self.base_a = self._commit(self.source_git, [], "Repo A base")
        self.base_b = self._commit(self.target_git, [], "Repo B base")
        self.source_git.update_ref("refs/heads/main", self.base_a)
        self.target_git.update_ref("refs/heads/main", self.base_b)
        self.commit_map = {self.base_a: self.base_b}
        self.reverse_map = {self.base_b: [self.base_a]}

    def _init_repo(self, name):
        repo_dir = os.path.join(self.root, name)
        subprocess.run(
            ["git", "init", "-q", repo_dir],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )
        subprocess.run(
            ["git", "-C", repo_dir, "symbolic-ref", "HEAD", "refs/heads/main"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        )
        return GitAdapter(repo_dir)

    @staticmethod
    def _commit(git, parents, message):
        env = {
            "GIT_AUTHOR_NAME": "DAG Test", "GIT_AUTHOR_EMAIL": "dag@example.org",
            "GIT_COMMITTER_NAME": "DAG Test", "GIT_COMMITTER_EMAIL": "dag@example.org",
            "GIT_AUTHOR_DATE": "2025-01-01T00:00:00+00:00",
            "GIT_COMMITTER_DATE": "2025-01-01T00:00:00+00:00",
        }
        return git.commit_tree(git.mktree_z([]), parents, message + "\n", env=env)

    def _chain(self, git, base, count=3):
        commits = []
        parent = base
        for index in range(count):
            parent = self._commit(git, [parent], "linear commit {}".format(index))
            commits.append(parent)
        return commits

    def _merge(self, git, base):
        left = self._commit(git, [base], "left branch")
        right = self._commit(git, [base], "right branch")
        return self._commit(git, [left, right], "two-parent merge")


class TestDAGBuilder(_GitRepositories):
    def test_boundary_calculation_and_closure(self):
        # Both boundary commits are already ancestors of the published merge.
        external = self._commit(self.source_git, [self.base_a], "published side")
        published = self._commit(self.source_git, [self.base_a, external], "published merge")
        pending_main = self._commit(self.source_git, [published], "pending main")
        pending_side = self._commit(self.source_git, [external], "pending side")
        tip = self._commit(self.source_git, [pending_main, pending_side], "pending merge")
        self.source_git.update_ref("refs/heads/main", tip)

        broken = DAGBuilder(self.source_git, self.target_git, {published: self.base_b})
        with self.assertRaisesRegex(DAGEngineError, "External parent boundary check failed"):
            broken.compute_sync_plan(tip, published)

        complete_map = {published: self.base_b, external: self.base_b}
        builder = DAGBuilder(self.source_git, self.target_git, complete_map)
        commits, boundary = builder.compute_sync_plan("refs/heads/main", published)
        self.assertEqual(set(commits), {pending_main, pending_side, tip})
        self.assertEqual(commits[-1], tip)
        self.assertEqual(boundary, {published, external})

    def test_linear_plan_has_ordered_commits_and_anchor_boundary(self):
        chain = self._chain(self.source_git, self.base_a)
        builder = DAGBuilder(self.source_git, self.target_git, self.commit_map)
        self.assertEqual(
            builder.compute_sync_plan(chain[-1], self.base_a, enforce_linear=True),
            (chain, {self.base_a}),
        )

    def test_unchanged_tip_has_empty_plan(self):
        builder = DAGBuilder(self.source_git, self.target_git, {})
        self.assertEqual(builder.compute_sync_plan(self.base_a, self.base_a), ([], set()))
        self.assertEqual(
            builder.compute_sync_plan(self.base_a, self.base_a, enforce_linear=True), ([], set())
        )

    def test_missing_anchor_mapping_fails_closed(self):
        chain = self._chain(self.source_git, self.base_a)
        with self.assertRaisesRegex(DAGEngineError, "External parent boundary check failed"):
            DAGBuilder(self.source_git, self.target_git, {}).compute_sync_plan(chain[-1], self.base_a)

    def test_phase1_rejects_forward_merge_at2_15_but_legacy_allows_it(self):
        tip = self._merge(self.source_git, self.base_a)
        builder = DAGBuilder(self.source_git, self.target_git, self.commit_map)
        commits, boundary = builder.compute_sync_plan(tip, self.base_a)
        self.assertEqual(len(commits), 3)
        self.assertEqual(boundary, {self.base_a})
        with self.assertRaisesRegex(NonLinearHistoryError, "S_NON_LINEAR_HALT"):
            builder.compute_sync_plan(tip, self.base_a, enforce_linear=True)

    def test_linear_validation_rejects_roots_gaps_reordering_and_missing_tip(self):
        chain = self._chain(self.source_git, self.base_a)
        builder = DAGBuilder(self.source_git, self.target_git, self.commit_map)
        intervals = [[], [self.base_a] + chain, chain[1:], chain[:-1], list(reversed(chain))]
        for interval in intervals:
            with self.subTest(interval=interval):
                with patch.object(self.source_git, "rev_list_topo", return_value=interval):
                    with self.assertRaises(NonLinearHistoryError):
                        builder.compute_sync_plan(chain[-1], self.base_a, enforce_linear=True)

    def test_unresolvable_tip_and_anchor_raise_engine_errors(self):
        builder = DAGBuilder(self.source_git, self.target_git, self.commit_map)
        with self.assertRaisesRegex(DAGEngineError, "Cannot resolve source tip"):
            builder.compute_sync_plan("refs/heads/missing", self.base_a)
        with self.assertRaisesRegex(DAGEngineError, "Cannot resolve last published A commit"):
            builder.compute_sync_plan(self.base_a, "refs/heads/missing")

    def test_non_fast_forward_source_raises_engine_error(self):
        unrelated = self._commit(self.source_git, [], "unrelated root")
        with self.assertRaisesRegex(DAGEngineError, "Source history diverged"):
            DAGBuilder(self.source_git, self.target_git, self.commit_map).compute_sync_plan(
                unrelated, self.base_a
            )


class TestBidirectionalDAGPlanner(_GitRepositories):
    def setUp(self):
        super().setUp()
        self.planner = BidirectionalDAGPlanner(
            self.source_git, self.target_git, self.commit_map, self.reverse_map
        )

    def test_s0_up_to_date(self):
        for direction in ["auto", "a2b", "b2a"]:
            with self.subTest(direction=direction):
                self.assertEqual(self.planner.determine_sync_state(
                    self.base_a, self.base_b, self.base_a, self.base_b,
                    requested_direction=direction,
                ), {"state": "S0_UP_TO_DATE", "direction": None, "commits": []})

    def test_s1_forward_a2b(self):
        chain = self._chain(self.source_git, self.base_a)
        for direction in ["auto", "a2b"]:
            with self.subTest(direction=direction):
                self.assertEqual(self.planner.determine_sync_state(
                    chain[-1], self.base_b, self.base_a, self.base_b,
                    requested_direction=direction,
                ), {
                    "state": "S1_FORWARD_A2B", "direction": "A2B",
                    "commits": chain, "boundary": {self.base_a},
                })

    def test_s2_reverse_b2a(self):
        chain = self._chain(self.target_git, self.base_b)
        # Many-to-one forward folds remain valid when the selected anchor is a member.
        self.reverse_map[self.base_b].insert(0, "another-folded-a-commit")
        for direction in ["auto", "b2a"]:
            with self.subTest(direction=direction):
                self.assertEqual(self.planner.determine_sync_state(
                    self.base_a, chain[-1], self.base_a, self.base_b,
                    requested_direction=direction,
                ), {
                    "state": "S2_REVERSE_B2A", "direction": "B2A",
                    "commits": chain, "boundary": {self.base_b},
                })

    def test_s3_concurrent_halt_for_all_directions_at_13(self):
        tip_a = self._chain(self.source_git, self.base_a)[-1]
        tip_b = self._chain(self.target_git, self.base_b)[-1]
        for direction in ["auto", "a2b", "b2a"]:
            for enforce_linear in [True, False]:
                with self.subTest(direction=direction, enforce_linear=enforce_linear):
                    with self.assertRaisesRegex(ConcurrentDivergenceError, "S3_CONCURRENT_HALT"):
                        self.planner.determine_sync_state(
                            tip_a, tip_b, self.base_a, self.base_b,
                            requested_direction=direction, enforce_phase1_linear=enforce_linear,
                        )

    def test_s4_rewritten_halt_on_either_repository(self):
        unrelated_a = self._commit(self.source_git, [], "unrelated A")
        unrelated_b = self._commit(self.target_git, [], "unrelated B")
        advanced_a = self._chain(self.source_git, self.base_a)[-1]
        advanced_b = self._chain(self.target_git, self.base_b)[-1]
        snapshots = [
            (unrelated_a, self.base_b), (self.base_a, unrelated_b),
            (unrelated_a, unrelated_b), (unrelated_a, advanced_b), (advanced_a, unrelated_b),
        ]
        for tip_a, tip_b in snapshots:
            for direction in ["auto", "a2b", "b2a"]:
                with self.subTest(tip_a=tip_a, tip_b=tip_b, direction=direction):
                    with self.assertRaisesRegex(HistoryRewrittenError, "S4_REWRITTEN_HALT"):
                        self.planner.determine_sync_state(
                            tip_a, tip_b, self.base_a, self.base_b, requested_direction=direction
                        )

    def test_s4_rejects_backward_tip(self):
        last_a = self._chain(self.source_git, self.base_a)[-1]
        with self.assertRaisesRegex(HistoryRewrittenError, "S4_REWRITTEN_HALT"):
            self.planner.determine_sync_state(self.base_a, self.base_b, last_a, self.base_b)

    def test_direction_mismatch_when_only_one_repository_advanced(self):
        tip_a = self._chain(self.source_git, self.base_a)[-1]
        tip_b = self._chain(self.target_git, self.base_b)[-1]
        with self.assertRaisesRegex(DAGEngineError, "Direction mismatch: requested b2a"):
            self.planner.determine_sync_state(
                tip_a, self.base_b, self.base_a, self.base_b, requested_direction="b2a"
            )
        with self.assertRaisesRegex(DAGEngineError, "Direction mismatch: requested a2b"):
            self.planner.determine_sync_state(
                self.base_a, tip_b, self.base_a, self.base_b, requested_direction="a2b"
            )

    def test_reverse_anchor_requires_both_maps(self):
        tip_b = self._chain(self.target_git, self.base_b)[-1]
        invalid_maps = [
            ({}, self.reverse_map), ({self.base_a: "wrong-target"}, self.reverse_map),
            (self.commit_map, {}), (self.commit_map, {self.base_b: ["another-a"]}),
        ]
        for forward, reverse in invalid_maps:
            with self.subTest(forward=forward, reverse=reverse):
                planner = BidirectionalDAGPlanner(self.source_git, self.target_git, forward, reverse)
                with self.assertRaisesRegex(DAGEngineError, "Reverse anchor check failed"):
                    planner.determine_sync_state(self.base_a, tip_b, self.base_a, self.base_b)

    def test_phase1_forward_merge_halts_at2_15(self):
        tip_a = self._merge(self.source_git, self.base_a)
        with self.assertRaisesRegex(NonLinearHistoryError, "NON_LINEAR_TOPOLOGY_HALT"):
            self.planner.determine_sync_state(tip_a, self.base_b, self.base_a, self.base_b)
        legacy_plan = self.planner.determine_sync_state(
            tip_a, self.base_b, self.base_a, self.base_b, enforce_phase1_linear=False
        )
        self.assertEqual(legacy_plan["state"], "S1_FORWARD_A2B")
        self.assertEqual(len(legacy_plan["commits"]), 3)

    def test_reverse_merge_halts_at_12_even_if_forward_linear_check_disabled(self):
        tip_b = self._merge(self.target_git, self.base_b)
        for enforce_linear in [True, False]:
            with self.subTest(enforce_linear=enforce_linear):
                with self.assertRaisesRegex(NonLinearHistoryError, "S_NON_LINEAR_HALT"):
                    self.planner.determine_sync_state(
                        self.base_a, tip_b, self.base_a, self.base_b,
                        enforce_phase1_linear=enforce_linear,
                    )

    def test_reverse_chain_must_start_at_anchor_and_reach_tip(self):
        chain = self._chain(self.target_git, self.base_b)
        for interval in [[], [self.base_b] + chain, chain[1:], chain[:-1], list(reversed(chain))]:
            with self.subTest(interval=interval):
                with patch.object(self.target_git, "rev_list_topo", return_value=interval):
                    with self.assertRaises(NonLinearHistoryError):
                        self.planner.determine_sync_state(
                            self.base_a, chain[-1], self.base_a, self.base_b
                        )


_LOCK_PROBE = """
import sys
sys.path.insert(0, sys.argv[2])
from engine.process_lock import LockBusyError, ProcessLock
lock = ProcessLock(sys.argv[1])
try:
    lock.acquire("child-probe")
except LockBusyError:
    print("busy")
    sys.exit(3)
else:
    lock.release()
    print("acquired")
"""


class TestProcessLock(_TemporaryWorkspace):
    def setUp(self):
        super().setUp()
        self.lock_path = os.path.join(self.root, "sync.lock")
        self.lock = ProcessLock(self.lock_path)
        self.addCleanup(self.lock.release)
        self.engine_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

    def _probe(self):
        return subprocess.run(
            [sys.executable, "-c", _LOCK_PROBE, self.lock_path, self.engine_root],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )

    def _owner_bytes(self):
        os.lseek(self.lock.fd, 0, os.SEEK_SET)
        return os.read(self.lock.fd, 65536)

    def test_concurrent_process_cannot_acquire_or_truncate_owner_metadata_at_05(self):
        self.lock.acquire("owner-transaction")
        inode = os.stat(self.lock_path).st_ino
        metadata = self._owner_bytes()
        for _ in range(3):
            probe = self._probe()
            self.assertEqual(probe.returncode, 3, probe.stderr.decode())
            self.assertEqual(probe.stdout.strip(), b"busy")
            self.assertEqual(self._owner_bytes(), metadata)
        self.lock.release()
        self.assertTrue(os.path.isfile(self.lock_path))
        self.assertEqual(os.stat(self.lock_path).st_ino, inode)
        probe = self._probe()
        self.assertEqual(probe.returncode, 0, probe.stderr.decode())
        self.assertEqual(probe.stdout.strip(), b"acquired")
        self.assertEqual(os.stat(self.lock_path).st_ino, inode)

    def test_owner_metadata_is_json_with_pid_time_and_transaction(self):
        tx_id = generate_tx_id("test-repo", "B2A")
        self.lock.acquire(tx_id)
        metadata = json.loads(self._owner_bytes().decode("utf-8"))
        self.assertEqual(set(metadata), {"pid", "time_ns", "tx_id"})
        self.assertEqual(metadata["pid"], os.getpid())
        self.assertIsInstance(metadata["time_ns"], int)
        self.assertGreater(metadata["time_ns"], 0)
        self.assertEqual(metadata["tx_id"], tx_id)

    def test_release_is_idempotent_and_reuses_same_inode_without_trailing_json(self):
        self.lock.release()
        self.lock.acquire("long-transaction-" * 100)
        inode = os.stat(self.lock_path).st_ino
        self.lock.release()
        self.lock.release()
        self.lock.acquire("short")
        self.assertEqual(json.loads(self._owner_bytes().decode("utf-8"))["tx_id"], "short")
        self.assertEqual(os.stat(self.lock_path).st_ino, inode)

    def test_context_manager_releases_after_exception(self):
        with self.assertRaisesRegex(RuntimeError, "transaction failed"):
            with self.lock as acquired:
                self.assertIs(acquired, self.lock)
                self.assertIsNotNone(self.lock.fd)
                raise RuntimeError("transaction failed")
        self.assertIsNone(self.lock.fd)
        probe = self._probe()
        self.assertEqual(probe.returncode, 0, probe.stderr.decode())

    def test_reacquiring_owned_lock_does_not_drop_original_lock(self):
        self.lock.acquire("owner")
        with self.assertRaises(LockBusyError):
            self.lock.acquire("duplicate")
        probe = self._probe()
        self.assertEqual(probe.returncode, 3, probe.stderr.decode())

    def test_kernel_releases_lock_when_owner_process_exits(self):
        script = _LOCK_PROBE.replace('    lock.release()\n', '')
        probe = subprocess.run(
            [sys.executable, "-c", script, self.lock_path, self.engine_root],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
        )
        self.assertEqual(probe.returncode, 0, probe.stderr.decode())
        self.lock.acquire("after-process-exit")

    def test_windows_lock_and_unlock_both_use_first_byte(self):
        kernel = MagicMock(LK_NBLCK=2, LK_UNLCK=0)
        offsets = []
        kernel.locking.side_effect = lambda fd, mode, count: offsets.append(
            os.lseek(fd, 0, os.SEEK_CUR)
        )
        with patch("engine.process_lock.os.name", "nt"), patch.dict(sys.modules, {"msvcrt": kernel}):
            self.lock.acquire("windows-owner")
            fd = self.lock.fd
            self.lock.release()
        self.assertEqual(kernel.locking.call_args_list, [call(fd, 2, 1), call(fd, 0, 1)])
        self.assertEqual(offsets, [0, 0])
        self.assertTrue(os.path.exists(self.lock_path))

    def test_lock_failure_closes_descriptor_and_preserves_metadata(self):
        with open(self.lock_path, "wb") as stream:
            stream.write(b"existing-owner")
        kernel = MagicMock(LK_NBLCK=2)
        kernel.locking.side_effect = OSError("busy")
        with patch("engine.process_lock.os.name", "nt"), patch.dict(sys.modules, {"msvcrt": kernel}):
            with patch("engine.process_lock.os.close", wraps=os.close) as close_fd:
                with self.assertRaises(LockBusyError):
                    self.lock.acquire("contender")
                close_fd.assert_called_once()
        self.assertIsNone(self.lock.fd)
        with open(self.lock_path, "rb") as stream:
            self.assertEqual(stream.read(), b"existing-owner")

    @unittest.skipIf(os.name == "nt", "POSIX kernel lock API")
    def test_posix_uses_nonblocking_flock_and_open_without_truncate(self):
        import fcntl

        with patch("engine.process_lock.os.open", wraps=os.open) as open_fd:
            with patch("fcntl.flock", wraps=fcntl.flock) as flock:
                self.lock.acquire("posix-owner")
                fd = self.lock.fd
                self.lock.release()
        open_fd.assert_called_once_with(self.lock_path, os.O_CREAT | os.O_RDWR, 0o644)
        self.assertEqual(flock.call_args_list, [
            call(fd, fcntl.LOCK_EX | fcntl.LOCK_NB), call(fd, fcntl.LOCK_UN),
        ])

    @unittest.skipIf(os.name == "nt", "POSIX kernel lock failure API")
    def test_posix_lock_failure_closes_descriptor(self):
        with patch("fcntl.flock", side_effect=BlockingIOError("busy")):
            with patch("engine.process_lock.os.close", wraps=os.close) as close_fd:
                with self.assertRaises(LockBusyError):
                    self.lock.acquire()
                close_fd.assert_called_once()
        self.assertIsNone(self.lock.fd)
        self.lock.acquire("after-lock-failure")

    def test_metadata_failure_closes_descriptor_and_releases_lock(self):
        for operation in ["write", "fsync"]:
            with self.subTest(operation=operation):
                with patch("engine.process_lock.os." + operation, side_effect=OSError("disk error")):
                    with self.assertRaisesRegex(OSError, "disk error"):
                        self.lock.acquire("failed-writer")
                self.assertIsNone(self.lock.fd)
                self.lock.acquire("after-write-failure")
                self.lock.release()

    def test_partial_metadata_writes_are_completed_and_synced(self):
        real_write = os.write
        with patch("engine.process_lock.os.write", side_effect=lambda fd, data: real_write(fd, data[:5])):
            with patch("engine.process_lock.os.fsync", wraps=os.fsync) as fsync:
                self.lock.acquire("partial-write")
                fsync.assert_called_once_with(self.lock.fd)
        self.assertEqual(json.loads(self._owner_bytes().decode("utf-8"))["tx_id"], "partial-write")

    def test_unlock_failure_still_closes_descriptor(self):
        kernel = MagicMock(LK_NBLCK=2, LK_UNLCK=0)
        kernel.locking.side_effect = [None, OSError("unlock failure")]
        with patch("engine.process_lock.os.name", "nt"), patch.dict(sys.modules, {"msvcrt": kernel}):
            self.lock.acquire()
            with patch("engine.process_lock.os.close", wraps=os.close) as close_fd:
                with self.assertRaisesRegex(OSError, "unlock failure"):
                    self.lock.release()
                close_fd.assert_called_once()
        self.assertIsNone(self.lock.fd)

    def test_transaction_id_format_and_entropy_with_frozen_clocks(self):
        with patch("engine.process_lock.datetime") as utc_clock:
            utc_clock.now.return_value.strftime.return_value = "20250102T030405Z"
            with patch("engine.process_lock._monotonic_ns", return_value=123456789):
                tx_ids = {generate_tx_id("test_repo", "A2B") for _ in range(256)}
        self.assertEqual(len(tx_ids), 256)
        for tx_id in tx_ids:
            self.assertRegex(tx_id, r"^tx_20250102T030405Z_123456789_[0-9a-f]{12}_test_repo_A2B$")
        self.assertRegex(generate_tx_id("repo"), r"^tx_\d{8}T\d{6}Z_\d+_[0-9a-f]{12}_repo_SYNC$")

    def test_transaction_id_uses_native_nanosecond_clock_when_available(self):
        with patch("engine.process_lock.time.monotonic_ns", return_value=123456789, create=True):
            self.assertIn("_123456789_", generate_tx_id("repo"))
        with patch("engine.process_lock.time.time_ns", return_value=987654321, create=True):
            self.lock.acquire("native-clock")
        self.assertEqual(json.loads(self._owner_bytes().decode("utf-8"))["time_ns"], 987654321)


if __name__ == "__main__":
    unittest.main()
