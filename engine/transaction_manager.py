"""Durable, direction-neutral synchronization WAL and fail-closed recovery."""

import copy
import json
import os
import re
import shutil
import time
from typing import Dict, Optional, Tuple

from engine.git_adapter import GitAdapter, GitError

SUPPORTED_SCHEMA_VERSION = "2.3"
LEGACY_SENTINEL = "MIGRATED_TO_V23_ABORT_LEGACY_ENGINE\n"
TERMINAL_PHASES = {"committed", "aborted_clean", "rolled_back"}
ACTIVE_PHASES = {"preparing", "prepared", "materializing", "verified", "publish_requested",
                 "forward_repair_pending", "recovery_halted_diverged"}


class TransactionError(Exception):
    pass


class StateLedgerCorruptedError(TransactionError):
    pass


class UnsupportedStateSchemaVersionError(TransactionError):
    pass


class MigrationQuarantinedError(TransactionError):
    pass


class RecoveryPolicyMismatchError(TransactionError):
    pass


class RemoteProbeUnknownError(TransactionError):
    pass


class TransactionManager:
    SUPPORTED_SCHEMA_VERSION = SUPPORTED_SCHEMA_VERSION

    def __init__(self, repo_id: str, state_file_path: str, target_git: GitAdapter,
                 source_git: Optional[GitAdapter] = None,
                 legacy_state_file_path: Optional[str] = None,
                 allow_bootstrap_if_missing: bool = True):
        self.repo_id = repo_id
        self.state_file_path = os.path.abspath(state_file_path)
        self.target_git = target_git  # Always Repo B, even during a B2A transaction.
        self.source_git = source_git  # Always Repo A.
        self.legacy_state_file_path = legacy_state_file_path
        self.allow_bootstrap_if_missing = allow_bootstrap_if_missing
        self.state = self._load_or_init_state()
        if (not os.path.exists(self.state_file_path) and legacy_state_file_path
                and os.path.exists(legacy_state_file_path)):
            self.state = self.migrate_v22_to_v23(legacy_state_file_path)

    def _empty_state(self) -> dict:
        return {
            "schema_version": SUPPORTED_SCHEMA_VERSION,
            "min_compatible_engine_version": "2.3.0", "engine_version": "2.3.0",
            "repo_id": self.repo_id, "last_published_a": None, "last_published_b": None,
            "last_verified_tree_a": None, "last_verified_tree_b": None,
            "last_epoch_digest": None, "endpoint_binding": None,
            "baseline_physical_audit_epoch": None, "current_transaction": None,
            "commit_map": {}, "reverse_map": {}, "provenance_fold_map": {},
        }

    def _read_json(self, path: str) -> dict:
        try:
            with open(path, "r", encoding="utf-8") as stream:
                state = json.load(stream)
        except (OSError, ValueError, UnicodeError) as exc:
            raise StateLedgerCorruptedError(f"Cannot read state ledger '{path}': {exc}") from exc
        if not isinstance(state, dict):
            raise StateLedgerCorruptedError(f"State ledger must be an object: {path}")
        return state

    def _validate_state(self, state: dict, legacy: bool = False) -> None:
        version = state.get("schema_version")
        if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+(?:\.\d+)?", version):
            raise StateLedgerCorruptedError("State ledger lacks a valid schema_version")
        parts = tuple(int(p) for p in version.split("."))
        if parts[:2] > (2, 3) or (parts[:2] == (2, 3) and any(parts[2:])):
            raise UnsupportedStateSchemaVersionError(f"Unsupported state schema version: {version}")
        if version != ("2.2" if legacy else SUPPORTED_SCHEMA_VERSION):
            raise UnsupportedStateSchemaVersionError(f"Explicit migration required for schema {version}")
        required = {"repo_id", "last_published_a", "last_published_b", "current_transaction", "commit_map"}
        if not legacy:
            required.add("reverse_map")
        if not required.issubset(state) or state["repo_id"] != self.repo_id:
            raise StateLedgerCorruptedError("State ledger missing required fields or has a different repo_id")
        for key in ("last_published_a", "last_published_b"):
            if state[key] is not None and (not isinstance(state[key], str) or not state[key]):
                raise StateLedgerCorruptedError(f"Invalid state cursor: {key}")
        mappings = state["commit_map"]
        if not isinstance(mappings, dict) or any(
                not isinstance(a, str) or not a or not isinstance(b, str) or not b
                for a, b in mappings.items()):
            raise StateLedgerCorruptedError("Invalid commit_map")
        if not legacy:
            reverse = state["reverse_map"]
            if not isinstance(reverse, dict) or any(
                    not isinstance(b, str) or not isinstance(items, list)
                    or any(not isinstance(a, str) for a in items) for b, items in reverse.items()):
                raise StateLedgerCorruptedError("Invalid reverse_map")
            expected = {}
            for a, b in mappings.items():
                expected.setdefault(b, set()).add(a)
            if {b: set(items) for b, items in reverse.items()} != expected:
                raise StateLedgerCorruptedError("commit_map/reverse_map are inconsistent")
        tx = state["current_transaction"]
        if tx is not None:
            if not isinstance(tx, dict) or tx.get("phase") not in ACTIVE_PHASES | TERMINAL_PHASES | ({None} if legacy else set()):
                raise StateLedgerCorruptedError("Invalid transaction schema or phase")
            if not legacy and tx["phase"] not in TERMINAL_PHASES:
                fields = {"tx_id", "direction", "frozen_source_tip", "epoch_digest", "endpoint_binding",
                          "expected_old_target_remote", "expected_old_target_local", "target_branch_ref"}
                if not fields.issubset(tx) or tx["direction"] not in ("A2B", "B2A"):
                    raise StateLedgerCorruptedError("Active WAL lacks direction/epoch/snapshot fields")
                if tx["phase"] in {"verified", "publish_requested", "forward_repair_pending"} and (
                        not tx.get("candidate_oid") or not tx.get("final_tree_oid")):
                    raise StateLedgerCorruptedError("Active WAL lacks candidate fields")

    def _load_or_init_state(self) -> dict:
        if os.path.exists(self.state_file_path):
            state = self._read_json(self.state_file_path)
            self._validate_state(state)
            return state
        if not self.allow_bootstrap_if_missing and not (
                self.legacy_state_file_path and os.path.exists(self.legacy_state_file_path)):
            raise StateLedgerCorruptedError(f"State ledger missing; bootstrap disabled: {self.state_file_path}")
        return self._empty_state()

    @staticmethod
    def _durable_replace(path: str, data: bytes) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        temporary = path + ".tmp"
        with open(temporary, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            fd = os.open(os.path.dirname(os.path.abspath(path)), os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    def _save_state(self):
        data = json.dumps(self.state, indent=2, ensure_ascii=False).encode("utf-8")
        self._durable_replace(self.state_file_path, data)

    @staticmethod
    def _reverse_map(commit_map: dict) -> dict:
        reverse = {}
        for a, b in commit_map.items():
            reverse.setdefault(b, []).append(a)
        return reverse

    def migrate_v22_to_v23(self, v22_path: str, policy_digest: str = "",
                          endpoint_binding: Optional[dict] = None) -> dict:
        """Quarantine unjournaled work, isolate the old engine, and rebuild all maps.

        A durable backup precedes the non-JSON sentinel, which precedes the new
        ledger. A crash in that window can resume from the backup, never bootstrap.
        Logical/export/physical baseline admission is performed by the CLI before
        calling this adapter; remote publication is independently confirmed here.
        """
        v22_path = os.path.abspath(v22_path)
        if v22_path == self.state_file_path:
            raise TransactionError("Legacy and v2.3 ledgers must have distinct paths")
        if os.path.exists(self.state_file_path):
            existing = self._read_json(self.state_file_path)
            self._validate_state(existing)
            self.state = existing
            return existing
        with open(v22_path, "rb") as stream:
            original = stream.read()
        backup_path = v22_path + ".v22.bak"
        if original == LEGACY_SENTINEL.encode("utf-8"):
            if not os.path.isfile(backup_path):
                raise StateLedgerCorruptedError("Migration sentinel has no durable v2.2 backup")
            with open(backup_path, "rb") as stream:
                original = stream.read()
        try:
            old = json.loads(original.decode("utf-8"))
        except (ValueError, UnicodeError) as exc:
            raise StateLedgerCorruptedError(f"Corrupted legacy ledger: {v22_path}") from exc
        if not isinstance(old, dict):
            raise StateLedgerCorruptedError("Legacy ledger must be an object")
        self._validate_state(old, legacy=True)
        tx = old.get("current_transaction")
        phase = tx.get("phase") if tx else None
        if phase not in (None, "committed"):
            if phase in ("prepared", "verified"):
                raise MigrationQuarantinedError(
                    f"Legacy v2.2 transaction in phase {phase} lacks rollback journal; manual verification required")
            if (phase != "publish_requested" or not tx.get("candidate_oid")
                    or not tx.get("expected_old_b")):
                raise MigrationQuarantinedError(f"Legacy v2.2 transaction in phase {phase} requires manual verification")
            try:
                confirmed = self.target_git.ls_remote_ref("origin", "refs/heads/main")
            except GitError as exc:
                raise MigrationQuarantinedError("Legacy publication cannot be confirmed remotely") from exc
            if confirmed != tx["candidate_oid"]:
                raise MigrationQuarantinedError("Legacy publication not confirmed; manual verification required")
        migrated = self._empty_state()
        for key in ("last_published_a", "last_published_b", "last_verified_tree_b", "commit_map"):
            if key in old:
                migrated[key] = copy.deepcopy(old[key])
        migrated["provenance_fold_map"] = copy.deepcopy(
            old.get("provenance_fold_map", old.get("history_fold_exceptions", {})))
        if phase == "publish_requested":
            migrated["commit_map"].update(tx.get("pending_map", {}))
            source_tip = tx.get("source_tip") or tx.get("frozen_source_tip")
            if not source_tip:
                raise MigrationQuarantinedError("Legacy publication lacks frozen source cursor")
            migrated["last_published_a"] = source_tip
            migrated["last_published_b"] = tx["candidate_oid"]
            migrated["last_verified_tree_b"] = tx.get("final_tree_oid")
            migrated["commit_map"][source_tip] = tx["candidate_oid"]
        migrated["reverse_map"] = self._reverse_map(migrated["commit_map"])
        migrated["last_epoch_digest"] = policy_digest or None
        migrated["endpoint_binding"] = copy.deepcopy(endpoint_binding)
        migrated["migration"] = {"from_schema": "2.2", "legacy_path": v22_path}
        if os.path.exists(backup_path):
            with open(backup_path, "rb") as stream:
                if stream.read() != original:
                    raise MigrationQuarantinedError("Existing v2.2 backup differs; refusing to overwrite evidence")
        else:
            self._durable_replace(backup_path, original)
        self._durable_replace(v22_path, LEGACY_SENTINEL.encode("utf-8"))
        self.state = migrated
        self._save_state()
        return self.state

    def get_commit_map(self) -> Dict[str, str]:
        return self.state["commit_map"]

    def get_last_published(self) -> Tuple[Optional[str], Optional[str]]:
        return self.state["last_published_a"], self.state["last_published_b"]

    def get_last_verified_tree(self) -> Optional[str]:
        return self.state.get("last_verified_tree_b")

    def _transaction(self, phases=None) -> dict:
        tx = self.state.get("current_transaction")
        if not tx or (phases is not None and tx.get("phase") not in phases):
            raise TransactionError(f"No active transaction in required phase(s): {phases}")
        return tx

    def start_transaction(self, tx_id: str, source_tip: str,
                          expected_old_b: Optional[str] = None, policy_digest: str = "",
                          direction: str = "A2B", endpoint_binding: Optional[dict] = None,
                          target_branch_ref: str = "refs/heads/main",
                          expected_old_target_remote: Optional[str] = None,
                          expected_old_target_local: Optional[str] = None,
                          pre_tx_tree_target: Optional[str] = None,
                          epoch_digest: Optional[str] = None):
        """Persist preparing before staging/worker creation. source_tip is frozen."""
        previous = self.state.get("current_transaction")
        if previous and previous.get("phase") not in TERMINAL_PHASES:
            raise TransactionError("Cannot replace an unresolved WAL transaction")
        if (direction not in ("A2B", "B2A") or not re.fullmatch(r"[A-Za-z0-9_.-]+", tx_id)
                or tx_id in (".", "..")):
            raise TransactionError("Unsafe transaction id or invalid direction")
        if direction == "B2A" and self.source_git is None:
            raise TransactionError("Repo A adapter required for B2A transactions")
        expected = expected_old_target_remote if expected_old_target_remote is not None else expected_old_b
        if not expected or not source_tip or not target_branch_ref.startswith("refs/heads/"):
            raise TransactionError("A transaction requires frozen source and target snapshots")
        self.state["current_transaction"] = {
            "tx_id": tx_id, "phase": "preparing", "direction": direction,
            "source_tip": source_tip, "frozen_source_tip": source_tip,
            "expected_old_b": expected if direction == "A2B" else self.state["last_published_b"],
            "expected_old_target_remote": expected,
            "expected_old_target_local": expected_old_target_local or expected,
            "target_branch_ref": target_branch_ref, "pre_tx_tree_target": pre_tx_tree_target,
            "candidate_oid": None, "candidate_ref": f"refs/sync/candidates/{self.repo_id}/{tx_id}",
            "epoch_digest": epoch_digest if epoch_digest is not None else policy_digest,
            "policy_digest": epoch_digest if epoch_digest is not None else policy_digest,
            "endpoint_binding": copy.deepcopy(endpoint_binding or {}),
            "canonical_pending_map": {}, "pending_map": {}, "worktree_journal": None,
            "executor_lease": None, "start_time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        }
        self._save_state()

    def mark_prepared(self, worktree_journal=None, candidate_oid: Optional[str] = None,
                      final_tree_oid: Optional[str] = None,
                      canonical_pending_map: Optional[dict] = None):
        tx = self._transaction({"preparing"})
        tx.update(worktree_journal=copy.deepcopy(worktree_journal), phase="prepared")
        if candidate_oid is not None:
            tx["candidate_oid"] = candidate_oid
        if final_tree_oid is not None:
            tx["final_tree_oid"] = final_tree_oid
            tx["post_tx_tree_target"] = final_tree_oid
        if canonical_pending_map is not None:
            tx["canonical_pending_map"] = dict(canonical_pending_map)
        self._save_state()

    def mark_materializing(self, executor_lease: Optional[dict] = None):
        tx = self._transaction({"prepared"})
        tx.update(phase="materializing", executor_lease=copy.deepcopy(executor_lease))
        self._save_state()

    def mark_verified(self, candidate_oid: str, final_tree_oid: str,
                      pending_map: Optional[Dict[str, str]] = None,
                      canonical_pending_map: Optional[Dict[str, str]] = None):
        tx = self._transaction({"prepared", "materializing"})
        canonical = canonical_pending_map
        if canonical is None:
            canonical = (dict(pending_map or {}) if tx["direction"] == "A2B"
                         else {a: b for b, a in (pending_map or {}).items()})
        tx.update(candidate_oid=candidate_oid, final_tree_oid=final_tree_oid,
                  post_tx_tree_target=final_tree_oid, canonical_pending_map=dict(canonical),
                  pending_map=dict(canonical), phase="verified", executor_lease=None)
        self._save_state()

    def mark_publish_requested(self):
        tx = self._transaction({"verified"})
        tx["phase"] = "publish_requested"
        self._save_state()

    def commit_transaction(self):
        tx = self._transaction({"publish_requested", "forward_repair_pending"})
        candidate, frozen = tx.get("candidate_oid"), tx["frozen_source_tip"]
        if not candidate:
            raise TransactionError("Cannot seal transaction without a candidate")
        canonical = dict(tx.get("canonical_pending_map", {}))
        a_tip, b_tip = (frozen, candidate) if tx["direction"] == "A2B" else (candidate, frozen)
        canonical[a_tip] = b_tip
        self.state["commit_map"].update(canonical)
        self.state["reverse_map"] = self._reverse_map(self.state["commit_map"])
        self.state.update(last_published_a=a_tip, last_published_b=b_tip,
                          last_epoch_digest=tx["epoch_digest"],
                          endpoint_binding=copy.deepcopy(tx["endpoint_binding"]))
        tree_key = "last_verified_tree_b" if tx["direction"] == "A2B" else "last_verified_tree_a"
        self.state[tree_key] = tx["final_tree_oid"]
        tx.update(phase="committed", finish_time=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
        self._save_state()
        self._cleanup_staging(tx)

    def _active_target_git(self, tx: dict) -> GitAdapter:
        if tx.get("direction", "A2B") == "B2A":
            if self.source_git is None:
                raise TransactionError("Cannot recover B2A without Repo A adapter")
            return self.source_git
        return self.target_git

    def _git_dir(self, git: GitAdapter) -> str:
        return os.path.abspath(git._run_checked(["rev-parse", "--absolute-git-dir"]).decode().strip())

    def _cleanup_staging(self, tx: dict) -> None:
        tx_id = tx.get("tx_id", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+", tx_id) or tx_id in (".", ".."):
            raise StateLedgerCorruptedError("Unsafe staging transaction id")
        git = self._active_target_git(tx)
        staging = os.path.join(self._git_dir(git), "sync_staging", tx_id)
        if os.path.islink(staging):
            raise StateLedgerCorruptedError("Refusing symlink staging cleanup")
        if os.path.isdir(staging):
            shutil.rmtree(staging)
        ref = tx.get("candidate_ref")
        if ref:
            expected_ref = f"refs/sync/candidates/{self.repo_id}/{tx_id}"
            if ref != expected_ref:
                raise StateLedgerCorruptedError("Candidate reference outside transaction namespace")
            git._run_checked(["update-ref", "-d", ref])

    def _terminate_executor(self, tx: dict, materializer=None) -> None:
        lease = tx.get("executor_lease")
        if not lease:
            return
        # The materializer/bridge owns kernel-handle fencing. Never taskkill a PID
        # from an unverified ledger, and never proceed merely because it is old.
        terminator = getattr(materializer, "terminate_executor_lease", None)
        if not callable(terminator):
            bridge = getattr(materializer, "dlp_bridge", None)
            terminator = getattr(bridge, "terminate_executor_lease", None)
        if not callable(terminator):
            from engine.workspace_materializer import terminate_lingering_worker
            terminator = terminate_lingering_worker
        outcome = terminator(lease)
        if outcome is False or outcome == "unsupported_platform":
            raise TransactionError("Executor termination fence failed or is unsupported on this platform")
        tx["executor_lease"] = None
        self._save_state()

    @staticmethod
    def _require_gate(result, label: str) -> None:
        status = result[0] if isinstance(result, tuple) else result
        status = getattr(status, "value", status)
        if status is not True and status != "PASS":
            raise TransactionError(f"{label} failed or unknown: {result}")

    def _forward_repair_local_to_candidate(self, tx: dict, forward_repair_fn=None):
        """Repair the *candidate*, never a newer remote descendant, before sealing."""
        tx["phase"] = "forward_repair_pending"
        self._save_state()
        git = self._active_target_git(tx)
        branch, candidate = tx["target_branch_ref"], tx["candidate_oid"]
        try:
            if git.get_symbolic_head() != branch:
                raise TransactionError("Target HEAD does not point to the bound target branch")
            local = git.rev_parse(branch)
            if local not in (tx["expected_old_target_local"], candidate):
                raise TransactionError("Local target changed concurrently; refusing forward repair")
            if forward_repair_fn is not None:
                result = forward_repair_fn(tx)
                if result is not None:
                    self._require_gate(result, "Forward repair")
            else:
                from engine.workspace_materializer import WorkspaceMaterializer
                from engine.dlp_verifier import DlpVerifier
                materializer = WorkspaceMaterializer(git, git.repo_dir,
                                                     tx_id=tx["tx_id"] + "_repair",
                                                     direction=tx["direction"])
                old_tree, new_tree = tx.get("pre_tx_tree_target"), tx["final_tree_oid"]
                if not old_tree:
                    raise TransactionError("WAL lacks the pre-transaction target tree")
                if tx["direction"] == "B2A":
                    info = materializer.prepare_transaction_staging(
                        old_tree, new_tree, direction="B2A", allow_dirty=True)
                    def save_lease(lease):
                        tx["executor_lease"] = lease
                        self._save_state()
                    materializer.materialize_delta_unencrypted_via_old(
                        old_tree, new_tree, staging_info=info, lease_callback=save_lease)
                    tx["executor_lease"] = None
                    self._save_state()
                else:
                    materializer.materialize_delta(old_tree, new_tree)
                verifier = DlpVerifier(git, git.repo_dir)
                self._require_gate(verifier.verify_transaction_delta_gates(
                    tx["direction"], old_tree, new_tree), "Forward repair delta gates")
            if local != candidate:
                git.update_ref(branch, candidate, local)
            git.read_tree(branch)
        except Exception:
            # Publication is already confirmed. No path out of this state may
            # restore old backups or rewind the remote.
            tx["phase"] = "forward_repair_pending"
            self._save_state()
            raise

    def recover_interrupted_transaction(self, remote_name: str = "origin",
                                        current_policy_digest: Optional[str] = None,
                                        current_endpoint_binding: Optional[dict] = None,
                                        materializer=None, verifier=None,
                                        forward_repair_fn=None) -> str:
        tx = self.state.get("current_transaction")
        if not tx:
            return "none"
        phase = tx.get("phase")
        if phase in TERMINAL_PHASES:
            if phase == "committed":
                self._cleanup_staging(tx)
            return "none"
        if current_policy_digest is not None and tx.get("epoch_digest") != current_policy_digest:
            raise RecoveryPolicyMismatchError("Recovery epoch_digest differs from the frozen transaction")
        if current_endpoint_binding is not None and tx.get("endpoint_binding") != current_endpoint_binding:
            raise RecoveryPolicyMismatchError("Recovery endpoint_binding differs from the frozen transaction")
        self._terminate_executor(tx, materializer)
        if phase == "preparing":
            self._cleanup_staging(tx)
            tx["phase"] = "aborted_clean"
            self._save_state()
            return "replayed"
        if phase in ("prepared", "materializing", "verified"):
            if tx.get("worktree_journal") is not None:
                if materializer is None:
                    raise TransactionError("Recovery requires the journal's physical-preserving materializer")
                materializer.rollback_from_journal(tx["worktree_journal"], direction=tx["direction"])
            elif phase != "prepared":
                raise TransactionError("Cannot roll back a touched worktree without a durable journal")
            self._cleanup_staging(tx)
            tx["phase"] = "rolled_back"
            self._save_state()
            return "replayed"
        if phase not in ("publish_requested", "forward_repair_pending"):
            raise TransactionError(f"Recovery halted for transaction phase {phase}")
        git = self._active_target_git(tx)
        branch, candidate = tx["target_branch_ref"], tx["candidate_oid"]
        expected = tx["expected_old_target_remote"]
        try:
            remote_oid = git.ls_remote_ref(remote_name, branch)
        except GitError as exc:
            raise RemoteProbeUnknownError("R-UNREACHABLE: remote status unknown; WAL retained") from exc
        if remote_oid == expected:
            if phase == "forward_repair_pending":
                raise TransactionError("Confirmed publication was rewound remotely; refusing to republish")
            ancestry = git.check_is_ancestor_tri_state(expected, candidate, remote_name, branch)
            if ancestry != "TRUE":
                raise TransactionError(f"R-OLD: candidate fast-forward not proven ({ancestry}); refusing push")
            if verifier is not None:
                self._require_gate(verifier.verify_transaction_delta_gates(
                    tx["direction"], tx["pre_tx_tree_target"], tx["final_tree_oid"]),
                    "Pre-publication delta gates")
            ok, message = git.push_ref(remote_name, tx.get("candidate_ref") or candidate, branch,
                                       no_follow_tags=True, expected_old_remote_oid=expected)
            if not ok:
                raise TransactionError(f"R-OLD: leased push rejected: {message}")
            try:
                confirmed = git.ls_remote_ref(remote_name, branch)
            except GitError as exc:
                raise RemoteProbeUnknownError("R-UNREACHABLE: push outcome unknown; WAL retained") from exc
            if confirmed != candidate:
                raise TransactionError("Publication changed during confirmation; recover again without rollback")
            action = "retried_push_and_committed"
        elif remote_oid == candidate:
            action = "advanced_to_committed"
        else:
            ancestry = (git.check_is_ancestor_tri_state(candidate, remote_oid, remote_name, branch)
                        if remote_oid else "FALSE")
            if ancestry == "UNKNOWN":
                raise RemoteProbeUnknownError("Remote graph unknown; refusing to classify as divergence")
            if ancestry != "TRUE":
                tx["phase"] = "recovery_halted_diverged"
                self._save_state()
                raise TransactionError(f"R-DIVERGED_OR_MISSING: remote={remote_oid}, candidate={candidate}")
            action = "descendant_repaired_and_committed"
        self._forward_repair_local_to_candidate(tx, forward_repair_fn)
        self.commit_transaction()
        return action
