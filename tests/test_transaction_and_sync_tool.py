"""Self-contained Git acceptance tests; real Windows DLP remains integration-only."""

import contextlib
import copy
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import sync_tool
from engine.config_loader import SyncConfig, compute_endpoint_binding, compute_epoch_digest
from engine.dlp_verifier import DlpVerifier, GateStatus
from engine.git_adapter import GitAdapter, GitError
from engine.process_lock import ProcessLock, LockBusyError
from engine.transaction_manager import (
    TransactionManager, TransactionError, StateLedgerCorruptedError,
    UnsupportedStateSchemaVersionError, MigrationQuarantinedError,
    RecoveryPolicyMismatchError, RemoteProbeUnknownError, LEGACY_SENTINEL,
)
from engine.tree_projector import TreeProjector
from engine.exclude_engine import ExcludeEngine
from engine.workspace_materializer import WorkspaceMaterializer, TSD_MAGIC_HEADER


class GitFixture(unittest.TestCase):
    ENV = {
        "GIT_AUTHOR_NAME": "Sync Test", "GIT_AUTHOR_EMAIL": "sync@example.org",
        "GIT_COMMITTER_NAME": "Sync Test", "GIT_COMMITTER_EMAIL": "sync@example.org",
        "GIT_AUTHOR_DATE": "2025-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2025-01-01T00:00:00+00:00",
    }
    PRIVATE = {"docs/private.docx": b"\x00private office\r\n",
               "gwp_debug/private.c": b"private debug\n",
               "app/DOT/private.c": ("100755", b"private app\n")}

    def setUp(self):
        parent = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                              "../../../.playground/sync/tmp_transaction_tests"))
        os.makedirs(parent, exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(dir=parent)
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        config_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../configs"))
        with open(os.path.join(config_root, "manifest_smart.json"), encoding="utf-8") as stream:
            self.manifest = json.load(stream)
        with open(os.path.join(config_root, "exclude_rules.json"), encoding="utf-8") as stream:
            self.rules = json.load(stream)
        self.create_pair("default")

    def create_pair(self, label):
        root = os.path.join(self.root, label)
        os.makedirs(root)
        self.git_a, self.git_b = self.init_repo(root, "a"), self.init_repo(root, "b")
        self.files_a = {"component/main.c": b"int main(void) { return 0; }\n", **self.PRIVATE}
        self.files_b = {"component/main.c": b"int main(void) { return 0; }\n"}
        self.a0 = self.commit(self.git_a, self.files_a, message="A anchor")
        self.b0 = self.commit(self.git_b, self.files_b, message="B anchor")
        for git, tip in ((self.git_a, self.a0), (self.git_b, self.b0)):
            self.push(git, tip)
            git.fetch_ref("origin", "+refs/heads/main:refs/remotes/origin/main")
        self.repo = {
            "repo_id": "sample", "description": "fixture", "enabled": True,
            "source": {"local_path": self.git_a.repo_dir, "url": self.git_a.get_remote_url(), "branch": "main"},
            "target": {"local_path": self.git_b.repo_dir, "url": self.git_b.get_remote_url(), "branch": "main"},
            "manifest": copy.deepcopy(self.manifest), "exclude_rules": copy.deepcopy(self.rules),
            "identity_map": {"Sync Test <sync@example.org>": "Sync Test <sync@example.org>"},
            "approved_external_identities": [], "message_sanitization_rules": [],
            "state_file": os.path.join(root, "state_sample.json"),
            "legacy_state_file": os.path.join(root, "state_sample.json"),
            "state_file_v23": os.path.join(root, "state_sample_v23.json"),
        }
        self.binding = compute_endpoint_binding(self.git_a, self.git_b, self.repo)
        self.epoch = compute_epoch_digest(self.repo, self.binding)
        self.app = object.__new__(sync_tool.SyncApp)
        self.app.base_dir = root
        self.app.config = Mock()
        self.app.config.repositories = [self.repo]
        self.app.config.global_settings = {"identity_map": self.repo["identity_map"]}
        self.app.lock_file_path = os.path.join(root, ".sync.lock")

    def init_repo(self, root, name):
        path, remote = os.path.join(root, name), os.path.join(root, name + ".git")
        for target, bare in ((path, False), (remote, True)):
            args = ["git", "init", "-q"] + (["--bare"] if bare else []) + [target]
            subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            subprocess.run(["git", "-C", target, "symbolic-ref", "HEAD", "refs/heads/main"], check=True)
        git = GitAdapter(path)
        git._run_checked(["config", "user.name", "Sync Test"])
        git._run_checked(["config", "user.email", "sync@example.org"])
        git._run_checked(["config", "core.autocrlf", "false"])
        git._run_checked(["remote", "add", "origin", remote])
        return git

    def tree(self, git, files):
        root = {}
        for path, value in files.items():
            mode, data = value if isinstance(value, tuple) else ("100644", value)
            cur = root
            parts = path.split("/")
            for part in parts[:-1]:
                cur = cur.setdefault(part, {})
            cur[parts[-1]] = (mode, "blob", git.hash_object_write(data))
        def build(node):
            records = []
            for name, value in node.items():
                records.append(("040000", "tree", build(value), name) if isinstance(value, dict)
                               else (*value, name))
            return git.mktree_z(records)
        return build(root)

    def commit(self, git, files, parents=(), message="change", checkout=True):
        oid = git.commit_tree(self.tree(git, files), list(parents), message, env=self.ENV)
        if checkout:
            git.update_ref("refs/heads/main", oid)
            git._run_checked(["reset", "--hard", "main"])
        return oid

    def push(self, git, oid, expected=None):
        ok, message = git.push_ref("origin", oid, "refs/heads/main", expected_old_remote_oid=expected)
        self.assertTrue(ok, message)

    def manager(self, save=True):
        manager = TransactionManager("sample", self.repo["state_file_v23"], self.git_b, self.git_a)
        manager.state.update(last_published_a=self.a0, last_published_b=self.b0,
                             commit_map={self.a0: self.b0}, reverse_map={self.b0: [self.a0]},
                             last_epoch_digest=self.epoch, endpoint_binding=self.binding,
                             baseline_physical_audit_epoch=self.epoch)
        if save:
            manager._save_state()
        return manager

    def verifier(self, git, worktree):
        # Model an approved external physical observer, NOT a real DLP driver.
        def physical(path):
            with open(path, "rb") as stream:
                plain = stream.read()
            if os.path.commonpath([path, self.git_b.repo_dir]) == self.git_b.repo_dir and plain and path.endswith(".c"):
                return TSD_MAGIC_HEADER + b"\x00" * (8192 - len(TSD_MAGIC_HEADER))
            return plain
        return DlpVerifier(git, worktree, physical_reader=physical)

    def live(self, **kwargs):
        with patch.object(sync_tool, "DlpVerifier", side_effect=self.verifier):
            return self.app.run_sync(**kwargs)

    @staticmethod
    def snapshot(root):
        result = {}
        for base, dirs, files in os.walk(root):
            for name in files:
                path = os.path.join(base, name)
                with open(path, "rb") as stream:
                    result[os.path.relpath(path, root)] = stream.read()
        return result

    def remote_commit(self, git, files, message="remote child"):
        path = os.path.join(self.root, "remote_writer_" + str(len(os.listdir(self.root))))
        subprocess.run(["git", "clone", "-q", git.get_remote_url(), path], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        writer = GitAdapter(path)
        parent = writer.rev_parse("HEAD")
        oid = self.commit(writer, files, [parent], message)
        self.push(writer, oid)
        return oid


class TestTransactionRecovery(GitFixture):
    def prepare(self, direction="A2B", non_ff=False):
        manager = self.manager()
        target = self.git_b if direction == "A2B" else self.git_a
        old = self.b0 if direction == "A2B" else self.a0
        files = dict(self.files_b if direction == "A2B" else self.files_a)
        files["component/main.c"] = b"int repaired = 1;\n"
        candidate = self.commit(target, files, [] if non_ff else [old], checkout=False)
        tree = target.rev_parse(candidate + "^{tree}")
        old_tree = target.rev_parse(old + "^{tree}")
        manager.start_transaction("tx_recovery", "frozen-source", policy_digest=self.epoch,
                                  direction=direction, endpoint_binding=self.binding,
                                  expected_old_target_remote=old, expected_old_target_local=old,
                                  pre_tx_tree_target=old_tree)
        tx = manager.state["current_transaction"]
        target.update_ref(tx["candidate_ref"], candidate)
        manager.mark_prepared([], candidate, tree)
        manager.mark_materializing()
        canonical = {"frozen-source": candidate} if direction == "A2B" else {candidate: "frozen-source"}
        manager.mark_verified(candidate, tree, canonical_pending_map=canonical)
        manager.mark_publish_requested()
        return manager, target, old, candidate, files

    def repair(self, target):
        def callback(tx):
            target._run_checked(["read-tree", "--reset", "-u", tx["candidate_oid"]])
            return True
        return callback

    def assert_sealed(self, manager, target, candidate, direction):
        self.assertEqual(manager.state["current_transaction"]["phase"], "committed")
        self.assertEqual(target.rev_parse("main"), candidate)
        self.assertEqual(target._run_checked(["write-tree"]).decode().strip(), target.rev_parse(candidate + "^{tree}"))
        self.assertEqual(target.status_porcelain_z(), [])
        a, b = manager.get_last_published()
        self.assertEqual((a, b), ("frozen-source", candidate) if direction == "A2B" else (candidate, "frozen-source"))
        self.assertEqual(manager.state["commit_map"][a], b)
        self.assertIn(a, manager.state["reverse_map"][b])

    def test_at04_r_old_retry_and_at205_non_ff_rejected_both_directions(self):
        for direction in ("A2B", "B2A"):
            for non_ff in (False, True):
                with self.subTest(direction=direction, non_ff=non_ff):
                    self.create_pair(direction + str(non_ff))
                    manager, target, old, candidate, _ = self.prepare(direction, non_ff)
                    before_remote = target.ls_remote_ref("origin", "refs/heads/main")
                    with patch.object(target, "push_ref", wraps=target.push_ref) as push:
                        if non_ff:
                            with self.assertRaisesRegex(TransactionError, "fast-forward not proven"):
                                manager.recover_interrupted_transaction(forward_repair_fn=self.repair(target))
                            push.assert_not_called()
                            self.assertEqual(target.ls_remote_ref("origin", "refs/heads/main"), before_remote)
                            self.assertEqual(manager.state["current_transaction"]["phase"], "publish_requested")
                        else:
                            result = manager.recover_interrupted_transaction(forward_repair_fn=self.repair(target))
                            self.assertEqual(result, "retried_push_and_committed")
                            self.assertEqual(push.call_args[1]["expected_old_remote_oid"], old)
                            self.assert_sealed(manager, target, candidate, direction)

    def test_at04_r_candidate_both_directions(self):
        for direction in ("A2B", "B2A"):
            with self.subTest(direction=direction):
                self.create_pair(direction)
                manager, target, _, candidate, _ = self.prepare(direction)
                self.push(target, candidate)
                self.assertEqual(manager.recover_interrupted_transaction(forward_repair_fn=self.repair(target)),
                                 "advanced_to_committed")
                self.assert_sealed(manager, target, candidate, direction)

    def test_at206_r_descendant_fetch_then_repair_exact_candidate_both_directions(self):
        for direction in ("A2B", "B2A"):
            with self.subTest(direction=direction):
                self.create_pair(direction)
                manager, target, _, candidate, files = self.prepare(direction)
                self.push(target, candidate)
                files["component/new.c"] = b"int newer = 2;\n"
                descendant = self.remote_commit(target, files)
                self.assertFalse(target.has_object(descendant))
                repaired = []
                def repair(tx):
                    self.assertTrue(target.has_object(descendant), "Graph must be fetched before local repair")
                    self.repair(target)(tx)
                    repaired.append(tx["candidate_oid"])
                    self.assertEqual(manager.state["last_published_a"], self.a0)
                    return True
                result = manager.recover_interrupted_transaction(forward_repair_fn=repair)
                self.assertEqual(result, "descendant_repaired_and_committed")
                self.assertEqual(repaired, [candidate])
                self.assert_sealed(manager, target, candidate, direction)
                self.assertEqual(target.ls_remote_ref("origin", "refs/heads/main"), descendant)
                self.assertNotIn(descendant, manager.state["commit_map"])
                self.assertNotIn(descendant, manager.state["reverse_map"])

    def test_at04_r_diverged_missing_and_unreachable_both_directions(self):
        for direction in ("A2B", "B2A"):
            for outcome in ("diverged", "missing", "unreachable", "graph_unknown"):
                with self.subTest(direction=direction, outcome=outcome):
                    self.create_pair(direction + outcome)
                    manager, target, _, candidate, files = self.prepare(direction)
                    if outcome == "unreachable":
                        with patch.object(target, "ls_remote_ref", side_effect=GitError("offline")):
                            with self.assertRaises(RemoteProbeUnknownError):
                                manager.recover_interrupted_transaction()
                        self.assertEqual(manager.state["current_transaction"]["phase"], "publish_requested")
                    elif outcome == "graph_unknown":
                        with patch.object(target, "ls_remote_ref", return_value="unknown"), patch.object(
                                target, "check_is_ancestor_tri_state", return_value="UNKNOWN"):
                            with self.assertRaises(RemoteProbeUnknownError):
                                manager.recover_interrupted_transaction()
                        self.assertEqual(manager.state["current_transaction"]["phase"], "publish_requested")
                    else:
                        remote = GitAdapter(target.get_remote_url())
                        if outcome == "missing":
                            remote._run_checked(["update-ref", "-d", "refs/heads/main"])
                        else:
                            diverged = self.commit(target, {"component/diverged.c": b"different\n"}, checkout=False)
                            self.push(target, diverged, remote.rev_parse("main"))
                        with self.assertRaisesRegex(TransactionError, "R-DIVERGED_OR_MISSING"):
                            manager.recover_interrupted_transaction(forward_repair_fn=self.repair(target))
                        self.assertEqual(manager.state["current_transaction"]["phase"], "recovery_halted_diverged")
                        self.assertNotEqual(target.rev_parse("main"), candidate)

    def test_published_forward_repair_failure_stays_pending_and_never_rolls_back(self):
        manager, target, _, candidate, _ = self.prepare()
        self.push(target, candidate)
        with self.assertRaisesRegex(RuntimeError, "gate failure"):
            manager.recover_interrupted_transaction(forward_repair_fn=Mock(side_effect=RuntimeError("gate failure")))
        self.assertEqual(manager.state["current_transaction"]["phase"], "forward_repair_pending")
        materializer = Mock()
        self.assertEqual(manager.recover_interrupted_transaction(materializer=materializer,
                         forward_repair_fn=self.repair(target)), "advanced_to_committed")
        materializer.rollback_from_journal.assert_not_called()

    def test_at208_epoch_and_endpoint_recovery_mismatch_precedes_any_probe(self):
        manager, target, _, _, _ = self.prepare()
        with patch.object(target, "ls_remote_ref") as probe:
            for kwargs in ({"current_policy_digest": "other"}, {"current_endpoint_binding": {"other": "endpoint"}}):
                with self.subTest(kwargs=kwargs), self.assertRaises(RecoveryPolicyMismatchError):
                    manager.recover_interrupted_transaction(**kwargs)
            probe.assert_not_called()

    def test_at211_preparing_cleanup_and_journal_rollback_with_lease_fence(self):
        for direction in ("A2B", "B2A"):
            for phase in ("preparing", "prepared", "materializing", "verified"):
                with self.subTest(direction=direction, phase=phase):
                    self.create_pair(direction + phase)
                    manager, target, _, _, _ = self.prepare(direction)
                    tx = manager.state["current_transaction"]
                    tx["phase"] = phase
                    tx["worktree_journal"] = [{"path": "component/main.c"}]
                    tx["executor_lease"] = {"worker_pid": 123, "worker_create_time_ft": 456}
                    staging = os.path.join(target.repo_dir, ".git", "sync_staging", tx["tx_id"])
                    os.makedirs(staging)
                    with open(os.path.join(staging, "half.bak"), "wb") as stream:
                        stream.write(b"partial")
                    events = []
                    mat = Mock()
                    mat.terminate_executor_lease.side_effect = lambda lease: events.append("fenced")
                    mat.rollback_from_journal.side_effect = lambda journal, direction: events.append("rollback")
                    self.assertEqual(manager.recover_interrupted_transaction(materializer=mat), "replayed")
                    self.assertEqual(events, ["fenced"] if phase == "preparing" else ["fenced", "rollback"])
                    self.assertFalse(os.path.exists(staging))
                    self.assertEqual(tx["phase"], "aborted_clean" if phase == "preparing" else "rolled_back")


class TestLedgerAndConfiguration(GitFixture):
    def test_at06_corrupted_json_and_invalid_schema_never_reset_or_rename(self):
        path = self.repo["state_file_v23"]
        for content in (b"{broken", b"[]", b"{}", b'{"schema_version":"2.3"}',
                        b'{"schema_version": 2.3}', b'null'):
            with self.subTest(content=content):
                with open(path, "wb") as stream:
                    stream.write(content)
                with self.assertRaises(StateLedgerCorruptedError):
                    TransactionManager("sample", path, self.git_b)
                with open(path, "rb") as stream:
                    self.assertEqual(stream.read(), content)
                self.assertFalse(any(".corrupted" in name for name in os.listdir(os.path.dirname(path))))
        with open(path, "w") as stream:
            json.dump({"schema_version": "3.0"}, stream)
        with self.assertRaises(UnsupportedStateSchemaVersionError):
            TransactionManager("sample", path, self.git_b)

    def legacy(self, phase=None):
        state = {"schema_version": "2.2", "repo_id": "sample", "last_published_a": self.a0,
                 "last_published_b": self.b0, "last_verified_tree_b": self.git_b.rev_parse(self.b0 + "^{tree}"),
                 "commit_map": {self.a0: self.b0, "another-a": self.b0, "older-a": "older-b"},
                 "reverse_map": {}, "history_fold_exceptions": [{"source_commit": "fold", "folded_to_target": self.b0}],
                 "current_transaction": None if phase is None else {"tx_id": "legacy_tx", "phase": phase}}
        with open(self.repo["legacy_state_file"], "w", encoding="utf-8") as stream:
            json.dump(state, stream)
        return state

    def test_at06_full_migration_reverse_map_backup_and_sentinel_blocks_old_json_reader(self):
        old = self.legacy()
        with open(self.repo["legacy_state_file"], "rb") as stream:
            original = stream.read()
        manager = TransactionManager("sample", self.repo["state_file_v23"], self.git_b, self.git_a)
        state = manager.migrate_v22_to_v23(self.repo["legacy_state_file"], self.epoch, self.binding)
        self.assertEqual(state["schema_version"], "2.3")
        self.assertEqual(state["reverse_map"][self.b0], [self.a0, "another-a"])
        self.assertEqual(state["reverse_map"]["older-b"], ["older-a"])
        self.assertEqual(state["provenance_fold_map"], old["history_fold_exceptions"])
        with open(self.repo["legacy_state_file"] + ".v22.bak", "rb") as stream:
            self.assertEqual(stream.read(), original)
        with open(self.repo["legacy_state_file"], "r") as stream:
            self.assertEqual(stream.read(), LEGACY_SENTINEL)
        # The unupgraded reader's actual json.load fails before it can overwrite.
        with open(self.repo["legacy_state_file"], "r") as stream, self.assertRaises(ValueError):
            json.load(stream)
        before = self.snapshot(os.path.dirname(self.repo["state_file_v23"]))
        manager.migrate_v22_to_v23(self.repo["legacy_state_file"])
        self.assertEqual(before, self.snapshot(os.path.dirname(self.repo["state_file_v23"])))

    def test_at207_active_legacy_prepared_verified_and_unconfirmed_publish_quarantined(self):
        for phase in ("prepared", "verified", "publish_requested"):
            with self.subTest(phase=phase):
                self.legacy(phase)
                before = self.snapshot(os.path.dirname(self.repo["legacy_state_file"]))
                manager = TransactionManager("sample", self.repo["state_file_v23"], self.git_b)
                with self.assertRaises(MigrationQuarantinedError):
                    manager.migrate_v22_to_v23(self.repo["legacy_state_file"])
                self.assertEqual(before, self.snapshot(os.path.dirname(self.repo["legacy_state_file"])))

    def test_confirmed_legacy_publish_and_resume_sentinel_window(self):
        old = self.legacy("publish_requested")
        old["current_transaction"].update(candidate_oid=self.b0, expected_old_b="old-b", source_tip="frozen-a",
                                          pending_map={"frozen-a": self.b0}, final_tree_oid=old["last_verified_tree_b"])
        legacy = self.repo["legacy_state_file"]
        with open(legacy + ".v22.bak", "w") as stream:
            json.dump(old, stream)
        with open(legacy, "w") as stream:
            stream.write(LEGACY_SENTINEL)
        manager = TransactionManager("sample", self.repo["state_file_v23"], self.git_b,
                                     legacy_state_file_path=legacy, allow_bootstrap_if_missing=False)
        self.assertEqual(manager.get_last_published(), ("frozen-a", self.b0))
        self.assertEqual(manager.state["reverse_map"][self.b0], [self.a0, "another-a", "frozen-a"])

    def test_missing_ledger_bootstrap_can_be_disabled(self):
        with self.assertRaisesRegex(StateLedgerCorruptedError, "bootstrap disabled"):
            TransactionManager("sample", self.repo["state_file_v23"], self.git_b,
                               allow_bootstrap_if_missing=False)
        self.assertFalse(os.path.exists(self.repo["state_file_v23"]))

    def test_at208_config_paths_and_epoch_cover_every_contract_input(self):
        root = os.path.join(self.root, "config")
        os.makedirs(os.path.join(root, "configs"))
        for name, data in (("manifest.json", self.manifest), ("rules.json", self.rules)):
            with open(os.path.join(root, "configs", name), "w") as stream:
                json.dump(data, stream)
        config = {"global_settings": {"identity_map": self.repo["identity_map"],
                                      "approved_external_identities": ["External <external@example.org>"]},
                  "repositories": [{"repo_id": "sample", "source": self.repo["source"], "target": self.repo["target"],
                                    "manifest_path": "configs/manifest.json", "exclude_rules_path": "configs/rules.json",
                                    "state_file": ".sync_state/state_smart.json"}]}
        with open(os.path.join(root, "configs", "sync_config.json"), "w") as stream:
            json.dump(config, stream)
        repo = SyncConfig(root).get_repo("sample")
        self.assertTrue(repo["state_file"].replace("\\", "/").endswith(".sync_state/state_smart.json"))
        self.assertEqual(repo["legacy_state_file"], repo["state_file"])
        self.assertTrue(repo["state_file_v23"].replace("\\", "/").endswith(".sync_state/state_sample_v23.json"))
        binding = compute_endpoint_binding(self.git_a, self.git_b, repo)
        digest = compute_epoch_digest(repo, binding)
        self.assertEqual(digest, compute_epoch_digest(dict(reversed(list(repo.items()))), dict(reversed(list(binding.items())))))
        for key in ("manifest", "exclude_rules", "identity_map", "approved_external_identities"):
            changed = copy.deepcopy(repo)
            if key == "approved_external_identities":
                changed[key].append("New <new@example.org>")
            else:
                changed[key]["epoch-test"] = True
            self.assertNotEqual(digest, compute_epoch_digest(changed, binding))
        for field in binding:
            changed = dict(binding)
            changed[field] += "-different"
            self.assertNotEqual(digest, compute_epoch_digest(repo, changed))
        for constant in ("NORMALIZER_SPEC_VERSION", "DLP_CONTRACT_SPEC_VERSION"):
            with patch("engine.config_loader." + constant, "future"):
                self.assertNotEqual(digest, compute_epoch_digest(repo, binding))
        self.git_b._run_checked(["remote", "set-url", "--push", "origin", "different-push-url"])
        self.assertNotEqual(binding, compute_endpoint_binding(self.git_a, self.git_b, repo))


class TestSyncTool(GitFixture):
    def test_at07_at215_dry_run_pending_wal_zero_production_writes_in_both_directions(self):
        for direction in ("A2B", "B2A"):
            with self.subTest(direction=direction):
                self.create_pair(direction)
                manager = self.manager()
                source, files, parent = ((self.git_a, self.files_a, self.a0) if direction == "A2B"
                                         else (self.git_b, self.files_b, self.b0))
                changed = dict(files, **{"component/main.c": b"int dryrun = 1;\n"})
                tip = self.commit(source, changed, [parent])
                self.push(source, tip)
                source.fetch_ref("origin", "+refs/heads/main:refs/remotes/origin/main")
                target, old = (self.git_b, self.b0) if direction == "A2B" else (self.git_a, self.a0)
                manager.start_transaction("production_pending", tip, old, self.epoch,
                                          direction=direction, endpoint_binding=self.binding,
                                          pre_tx_tree_target=target.rev_parse(old + "^{tree}"))
                manager.mark_prepared([], old, target.rev_parse(old + "^{tree}"))
                manager.mark_materializing()
                manager.mark_verified(old, target.rev_parse(old + "^{tree}"), canonical_pending_map={})
                manager.mark_publish_requested()
                manager.state["current_transaction"]["executor_lease"] = {"worker_pid": 98765, "state": "ACTIVE"}
                manager._save_state()
                before_a, before_b = self.snapshot(self.git_a.repo_dir), self.snapshot(self.git_b.repo_dir)
                with open(self.repo["state_file_v23"], "rb") as stream:
                    before_wal = stream.read()
                calls = []
                run_checked = GitAdapter._run_checked
                def trace(git, args, stdin_bytes=None, env=None):
                    calls.append((git.repo_dir, list(args), copy.deepcopy(env)))
                    return run_checked(git, args, stdin_bytes=stdin_bytes, env=env)
                output = io.StringIO()
                with patch.object(TransactionManager, "migrate_v22_to_v23", side_effect=AssertionError("migration")), \
                     patch.object(TransactionManager, "recover_interrupted_transaction", side_effect=AssertionError("recovery")), \
                     patch.object(GitAdapter, "_run_checked", trace), contextlib.redirect_stdout(output):
                    self.assertEqual(self.app.run_sync(dry_run=True), 0)
                self.assertIn("DRY-RUN WARNING", output.getvalue())
                self.assertEqual(before_a, self.snapshot(self.git_a.repo_dir))
                self.assertEqual(before_b, self.snapshot(self.git_b.repo_dir))
                with open(self.repo["state_file_v23"], "rb") as stream:
                    self.assertEqual(before_wal, stream.read())
                for path, args, env in calls:
                    self.assertNotIn(args[0], ("fetch", "update-ref", "read-tree", "push"))
                    if env and "GIT_OBJECT_DIRECTORY" in env:
                        self.assertEqual(path, target.repo_dir, "Never inject target objects into source Git")
                        self.assertIn("target_objects", env["GIT_OBJECT_DIRECTORY"])
                        self.assertFalse(os.path.exists(env["GIT_OBJECT_DIRECTORY"]), "Scratch must be cleaned")
                self.assertTrue(any(args[0] == "commit-tree" for _, args, _ in calls), "Dry-run must replay the full DAG")

    def test_at07_dry_run_with_legacy_state_does_not_migrate(self):
        old = {"schema_version": "2.2", "repo_id": "sample", "last_published_a": self.a0,
               "last_published_b": self.b0, "commit_map": {self.a0: self.b0}, "current_transaction": None}
        with open(self.repo["legacy_state_file"], "w") as stream:
            json.dump(old, stream)
        before = self.snapshot(os.path.dirname(self.repo["legacy_state_file"]))
        self.assertEqual(self.app.run_sync(dry_run=True), 0)
        self.assertFalse(os.path.exists(self.repo["state_file_v23"]))
        after = self.snapshot(os.path.dirname(self.repo["legacy_state_file"]))
        self.assertEqual({k: v for k, v in before.items()}, {k: after[k] for k in before})
        self.assertFalse(os.path.exists(self.repo["legacy_state_file"] + ".v22.bak"))

    def test_at11_authoritative_remote_source_ignores_stale_local_branch(self):
        self.manager()
        changed = dict(self.files_a, **{"component/main.c": b"int remote_only = 7;\n"})
        remote_tip = self.remote_commit(self.git_a, changed)
        self.assertEqual(self.git_a.rev_parse("main"), self.a0)
        self.assertEqual(self.live(), 0)
        manager = TransactionManager("sample", self.repo["state_file_v23"], self.git_b, self.git_a)
        self.assertEqual(manager.state["last_published_a"], remote_tip)
        self.assertEqual(self.git_a.rev_parse("main"), self.a0, "Never align or rewind the source branch")
        with open(os.path.join(self.git_b.repo_dir, "component/main.c"), "rb") as stream:
            self.assertEqual(stream.read(), b"int remote_only = 7;\n")
        self.assertEqual(self.live(), 0)

    def test_at11_force_with_lease_rejects_remote_rewind_during_publication(self):
        self.manager()
        changed = dict(self.files_a, **{"component/main.c": b"int leased = 1;\n"})
        tip = self.commit(self.git_a, changed, [self.a0])
        self.push(self.git_a, tip)
        rewound = self.commit(self.git_b, {"component/old.c": b"old root\n"}, checkout=False, message="rewind")
        self.git_b._run_checked(["push", "origin", f"{rewound}:refs/sync/rewind_seed"])
        push = GitAdapter.push_ref
        def rewind_then_push(git, remote, src, dst, **kwargs):
            if git.repo_dir == self.git_b.repo_dir:
                GitAdapter(git.get_remote_url()).update_ref(dst, rewound)
            return push(git, remote, src, dst, **kwargs)
        with patch.object(GitAdapter, "push_ref", rewind_then_push):
            with self.assertRaisesRegex(TransactionError, "leased push rejected"):
                self.live()
        self.assertEqual(self.git_b.ls_remote_ref("origin", "refs/heads/main"), rewound)
        manager = TransactionManager("sample", self.repo["state_file_v23"], self.git_b, self.git_a)
        self.assertEqual(manager.state["current_transaction"]["phase"], "publish_requested")
        self.assertEqual(manager.get_last_published(), (self.a0, self.b0))

    def test_at208_s0_epoch_changes_and_origin_push_url_changes_halt(self):
        manager = self.manager()
        for change in ("policy", "branch", "url"):
            with self.subTest(change=change):
                self.create_pair(change)
                self.manager()
                if change == "policy":
                    self.repo["exclude_rules"]["rule_version"] = "changed"
                elif change == "branch":
                    for git in (self.git_a, self.git_b):
                        git.update_ref("refs/heads/other", git.rev_parse("main"))
                        self.push_ref_other(git)
                    self.repo["target"]["branch"] = "other"
                else:
                    self.git_b._run_checked(["remote", "set-url", "--push", "origin", "unexpected"])
                with self.assertRaisesRegex(RecoveryPolicyMismatchError, "Epoch/endpoint changed"):
                    self.live()
        self.assertIsNotNone(manager)

    def push_ref_other(self, git):
        self.assertTrue(git.push_ref("origin", "refs/heads/other", "refs/heads/other")[0])

    def test_at209_s0_rejects_polluted_b_even_when_filtered_shared_norm_matches(self):
        for contamination in ({"docs/private.docx": b"private"}, {"component/leak.c": b"server=10.42.0.252\n"}):
            with self.subTest(contamination=contamination):
                self.create_pair("pollution" + str(len(contamination[next(iter(contamination))])))
                b = self.commit(self.git_b, {**self.files_b, **contamination}, [self.b0])
                self.push(self.git_b, b)
                manager = self.manager()
                manager.state.update(last_published_b=b, commit_map={self.a0: b}, reverse_map={b: [self.a0]})
                manager._save_state()
                with self.assertRaisesRegex(TransactionError, "ValidateExportTree"):
                    self.live()

    def test_at16_at18_round_trip_private_assets_no_ping_pong_and_concurrent_source(self):
        self.manager()
        before_private = {entry["path"]: (entry["mode"], entry["oid"]) for entry in self.git_a.ls_tree_r_z(self.a0)
                          if entry["path"] in self.PRIVATE}
        forward_files = dict(self.files_a, **{"component/main.c": b"int forward = 1;\n"})
        a1 = self.commit(self.git_a, forward_files, [self.a0])
        self.push(self.git_a, a1)
        self.assertEqual(self.live(), 0)
        b1 = self.git_b.rev_parse("main")
        reverse_files = {"component/main.c": b"int reverse = 2;\n", "component/new.c": ("100755", b"new\n")}
        b2 = self.commit(self.git_b, reverse_files, [b1], message="B change")
        self.push(self.git_b, b2)
        # A concurrent new source (B) commit arrives after B2A's frozen snapshot.
        push = GitAdapter.push_ref
        concurrent = []
        def inject_source_commit(git, remote, src, dst, **kwargs):
            if git.repo_dir == self.git_a.repo_dir and not concurrent:
                newer = dict(reverse_files, **{"component/new.c": ("100755", b"newer concurrent\n")})
                concurrent.append(self.remote_commit(self.git_b, newer))
            return push(git, remote, src, dst, **kwargs)
        with patch.object(GitAdapter, "push_ref", inject_source_commit):
            self.assertEqual(self.live(requested_direction="b2a"), 0)
        manager = TransactionManager("sample", self.repo["state_file_v23"], self.git_b, self.git_a)
        self.assertEqual(manager.state["last_published_b"], b2, "Only seal the frozen B source tip")
        self.assertEqual(self.git_b.ls_remote_ref("origin", "refs/heads/main"), concurrent[0])
        self.assertEqual(self.live(), 0, "Next cycle must replay the concurrent source commit")
        a_final = self.git_a.rev_parse("main")
        after_private = {entry["path"]: (entry["mode"], entry["oid"]) for entry in self.git_a.ls_tree_r_z(a_final)
                         if entry["path"] in self.PRIVATE}
        self.assertEqual(before_private, after_private)
        tips = (a_final, self.git_b.rev_parse("main"))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(self.live(), 0)
        self.assertIn("S0_UP_TO_DATE", output.getvalue())
        self.assertEqual(tips, (self.git_a.rev_parse("main"), self.git_b.rev_parse("main")))
        self.assertEqual(self.git_a.status_porcelain_z(), [])

    def test_at18_concurrent_a_source_commit_survives_a2b_publication(self):
        self.manager()
        files = dict(self.files_a, **{"component/main.c": b"first\n"})
        a1 = self.commit(self.git_a, files, [self.a0])
        self.push(self.git_a, a1)
        push = GitAdapter.push_ref
        newer = []
        def inject(git, remote, src, dst, **kwargs):
            if git.repo_dir == self.git_b.repo_dir and not newer:
                newer.append(self.remote_commit(self.git_a, dict(files, **{"component/main.c": b"second\n"})))
            return push(git, remote, src, dst, **kwargs)
        with patch.object(GitAdapter, "push_ref", inject):
            self.assertEqual(self.live(), 0)
        manager = TransactionManager("sample", self.repo["state_file_v23"], self.git_b, self.git_a)
        self.assertEqual(manager.state["last_published_a"], a1)
        self.assertEqual(self.git_a.ls_remote_ref("origin", "refs/heads/main"), newer[0])
        self.assertEqual(self.live(), 0)
        self.assertEqual(self.live(), 0)

    def test_process_lock_exclusion_and_cli_switches(self):
        with ProcessLock(self.app.lock_file_path):
            with self.assertRaises(LockBusyError):
                self.app.run_sync(dry_run=True)
        with patch.object(sync_tool, "SyncApp", return_value=self.app), patch.object(self.app, "run_sync", return_value=0) as run:
            self.assertEqual(sync_tool.main(["sync", "--repo", "sample", "--direction", "b2a", "--no-fetch",
                                             "--isolated-rehearsal", "sandbox"]), 0)
            run.assert_called_once_with(repo_id="sample", dry_run=False, requested_direction="b2a",
                                        no_fetch=True, isolated_rehearsal="sandbox")


if __name__ == "__main__":
    unittest.main()
