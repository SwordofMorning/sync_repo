#!/usr/bin/env python3
"""Bidirectional, endpoint-bound synchronization and read-only rehearsal CLI."""

import argparse
import copy
import json
import os
import shutil
import stat
import sys
import tempfile
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine.config_loader import (SyncConfig, ConfigError, compute_endpoint_binding,
                                  compute_epoch_digest)
from engine.content_normalizer import ContentNormalizer
from engine.dag_builder import BidirectionalDAGPlanner, DAGEngineError
from engine.dlp_verifier import DlpVerifier
from engine.exclude_engine import ExcludeEngine
from engine.git_adapter import GitAdapter, GitError
from engine.metadata_sanitizer import MetadataSanitizer, SanitizerError
from engine.process_lock import ProcessLock, LockBusyError, generate_tx_id
from engine.reverse_tree_projector import ReverseTreeProjector, ReverseProjectionError
from engine.transaction_manager import (TransactionManager, TransactionError,
                                        RecoveryPolicyMismatchError, LEGACY_SENTINEL)
from engine.tree_projector import TreeProjector, TreeProjectionError
from engine.workspace_materializer import WorkspaceMaterializer, MaterializeError


def _safe_rmtree(path: str) -> None:
    if os.path.exists(path):
        shutil.rmtree(path, onerror=lambda func, p, _exc: (os.chmod(p, stat.S_IWRITE), func(p)))


class _ObjectView:
    """Read a simulated target's objects; never change source/process environment."""
    def __init__(self, git, env=None):
        self.git, self.env = git, env

    def ls_tree_r_z(self, tree):
        return self.git.ls_tree_r_z(tree, env=self.env)

    def ls_tree_r_z_strict(self, tree):
        return self.git.ls_tree_r_z_strict(tree, env=self.env)

    def cat_file_blob(self, oid):
        return self.git.cat_file_blob(oid, env=self.env)

    def cat_file_blobs_batch(self, oids):
        return self.git.cat_file_blobs_batch(oids, env=self.env)


class SyncApp:
    def __init__(self, base_dir: str):
        self.base_dir = os.path.abspath(base_dir)
        self.config = SyncConfig(self.base_dir)
        self.lock_file_path = os.path.join(
            self.base_dir, self.config.global_settings.get("lock_file", ".sync.lock"))

    def run_sync(self, repo_id: Optional[str] = None, dry_run: bool = False,
                 requested_direction: str = "auto", no_fetch: bool = False,
                 isolated_rehearsal: Optional[str] = None):
        # A shared kernel lock, not an existence test or a replaceable PID file.
        with ProcessLock(self.lock_file_path):
            if requested_direction not in ("auto", "a2b", "b2a"):
                raise ConfigError("Direction must be auto, a2b, or b2a")
            repos = [r for r in self.config.repositories if repo_id is None or r["repo_id"] == repo_id]
            if not repos:
                print(f"[-] Repository '{repo_id}' not found.")
                return 1
            for repo in repos:
                if not repo.get("enabled", True):
                    continue
                # This dispatch MUST precede migration, recovery, and fetching.
                if dry_run:
                    self._sync_single_repo_dry_run(repo, requested_direction)
                elif isolated_rehearsal is not None:
                    self._isolated_rehearsal(repo, isolated_rehearsal, requested_direction, no_fetch)
                else:
                    self._sync_single_repo(repo, requested_direction=requested_direction, no_fetch=no_fetch)
            return 0

    @staticmethod
    def _state_path(repo):
        return repo.get("state_file_v23", repo["state_file"])

    def _read_state_memory(self, repo):
        # No constructor: it may migrate, recover, create directories, or persist.
        reader = object.__new__(TransactionManager)
        reader.repo_id = repo["repo_id"]
        path = self._state_path(repo)
        if os.path.exists(path):
            state = reader._read_json(path)
            reader._validate_state(state)
            return copy.deepcopy(state)
        legacy = repo.get("legacy_state_file", repo["state_file"])
        if os.path.exists(legacy):
            with open(legacy, "r", encoding="utf-8") as stream:
                sentinel = stream.read() == LEGACY_SENTINEL
            state = reader._read_json(legacy + ".v22.bak" if sentinel else legacy)
            reader._validate_state(state, legacy=True)
            state["reverse_map"] = reader._reverse_map(state["commit_map"])
            return state
        return reader._empty_state()

    @staticmethod
    def _branch_ref(endpoint):
        branch = endpoint.get("branch", "main")
        return branch if branch.startswith("refs/heads/") else "refs/heads/" + branch

    def _tips(self, repo, git_a, git_b, no_fetch=False):
        tips = []
        for key, git in (("source", git_a), ("target", git_b)):
            branch_ref = self._branch_ref(repo[key])
            tracking_ref = "refs/remotes/origin/" + branch_ref[len("refs/heads/"):]
            if not no_fetch:
                git._run_checked(["fetch", "--prune", "--no-tags", "origin",
                                  f"+{branch_ref}:{tracking_ref}"])
            # --no-fetch means use the last authoritative snapshot, NOT local HEAD.
            tips.append(git.rev_parse(tracking_ref))
        return tuple(tips)

    @staticmethod
    def _gate(result, label):
        TransactionManager._require_gate(result, label)

    def _validate_pair(self, policy, git_a, tree_a, git_b, tree_b, bridge=None):
        decrypt = (lambda raw: bridge.decrypt_blob_via_old_channel(raw)) if bridge else None
        self._gate(policy.validate_export_tree(git_b, tree_b, decrypt_fn=decrypt), "ValidateExportTree")
        norm = ContentNormalizer()
        ok, msg = policy.verify_shared_norm_pair(git_a, tree_a, git_b, tree_b, normalizer=norm, decrypt_fn=decrypt)
        if not ok:
            raise TransactionError(f"SharedNorm mismatch between Repo A and Repo B: {msg}")

    def _baseline_audit(self, git_a, git_b, repo=None):
        if repo and repo.get("legacy_anchor_b_oid"):
            # Legacy v2.2 repository baseline (18,700+ files cloned prior to v2.3)
            # is audited incrementally via 100% transaction delta gates.
            return
        for git, direction in ((git_a, "B2A"), (git_b, "A2B")):
            verifier = DlpVerifier(git, git.repo_dir)
            self._gate(verifier.verify_full_worktree_physical_baseline(
                git.rev_parse("HEAD^{tree}"), role="A" if direction == "B2A" else "B"), "Full physical baseline audit")

    def _bootstrap_memory(self, repo, state, git_a, git_b, tip_a, tip_b, policy, bridge=None):
        last_a, last_b = state.get("last_published_a"), state.get("last_published_b")
        if bool(last_a) != bool(last_b):
            raise TransactionError("Incomplete published anchor pair; explicit baseline required")
        if last_a:
            return
        anchor_a = repo.get("legacy_anchor_a_oid") or tip_a
        anchor_b = repo.get("legacy_anchor_b_oid") or tip_b
        anchor_a, anchor_b = git_a.rev_parse(anchor_a), git_b.rev_parse(anchor_b)
        self._validate_pair(policy, git_a, anchor_a, git_b, anchor_b, bridge)
        state["last_published_a"], state["last_published_b"] = anchor_a, anchor_b
        state.setdefault("commit_map", {})[anchor_a] = anchor_b
        state["reverse_map"] = TransactionManager._reverse_map(state["commit_map"])
        state["provenance_fold_map"] = copy.deepcopy(repo.get("history_fold_exceptions", []))

    def _plan(self, state, git_a, git_b, tip_a, tip_b, requested_direction, repo=None):
        enforce_linear = not bool(repo and repo.get("allow_forward_merges", False))
        return BidirectionalDAGPlanner(git_a, git_b, state["commit_map"], state["reverse_map"]).determine_sync_state(
            tip_a, tip_b, state["last_published_a"], state["last_published_b"],
            requested_direction=requested_direction, enforce_phase1_linear=enforce_linear)

    def _scratch_dir(self, prefix):
        parent = os.path.join(self.base_dir, ".playground", "sync")
        os.makedirs(parent, exist_ok=True)
        return tempfile.mkdtemp(prefix=prefix, dir=parent)

    def _replay(self, repo, state, plan, git_a, git_b, epoch, target_env=None, bridge=None, policy=None):
        """Object-only DAG replay, shared by live and isolated object-store dry-run."""
        direction = plan["direction"]
        if policy is None:
            policy = ExcludeEngine(repo["manifest"], repo["exclude_rules"])
        sanitizer = MetadataSanitizer(
            repo.get("identity_map", self.config.global_settings.get("identity_map", {})),
            repo.get("message_sanitization_rules", []),
            repo.get("approved_external_identities", self.config.global_settings.get("approved_external_identities", [])))
        canonical = {}
        if direction == "A2B":
            projector = TreeProjector(git_a, git_b, policy, policy_digest=epoch, target_env=target_env)
            seeded_pairs = set()
            if state.get("last_published_a") and state.get("last_published_b"):
                seeded_pairs.add((state["last_published_a"], state["last_published_b"]))
            for b_a in plan.get("boundary", ()):
                b_b = state.get("commit_map", {}).get(b_a)
                if b_b:
                    seeded_pairs.add((b_a, b_b))
            for b_a, b_b in seeded_pairs:
                projector.seed_from_baseline(b_a, b_b)
            for idx, commit_a in enumerate(plan["commits"], 1):
                tree = projector.project_commit_tree(commit_a)
                parents = []
                for parent in git_a.get_commit_parents(commit_a):
                    mapped = canonical.get(parent, state["commit_map"].get(parent))
                    if not mapped:
                        raise DAGEngineError(f"Missing canonical boundary parent {parent}")
                    parents.append(mapped)
                env, message = sanitizer.build_commit_env(git_a.get_commit_metadata(commit_a), direction=direction)
                env.update(target_env or {})
                candidate = git_b.commit_tree(tree, parents, message, env=env)
                canonical[commit_a] = candidate
                if idx == len(plan["commits"]):
                    self._validate_pair(policy, git_a, commit_a, _ObjectView(git_b, target_env), tree, bridge)
        else:
            projector = ReverseTreeProjector(git_a, git_b, policy, dlp_bridge=bridge, target_env_a=target_env)
            parent_a, parent_b = state["last_published_a"], state["last_published_b"]
            for commit_b in plan["commits"]:
                tree, _ = projector.project_reverse_commit_tree(parent_a, parent_b, commit_b)
                env, message = sanitizer.build_commit_env(git_b.get_commit_metadata(commit_b), direction=direction)
                env.update(target_env or {})
                candidate = git_a.commit_tree(tree, [parent_a], message, env=env)
                canonical[candidate] = commit_b
                self._validate_pair(policy, _ObjectView(git_a, target_env), tree, git_b, commit_b, bridge)
                parent_a, parent_b = candidate, commit_b
        if not plan["commits"]:
            raise DAGEngineError("Replay requires a non-empty linear interval")
        return candidate, tree, canonical

    def _sync_single_repo_dry_run(self, repo: dict, requested_direction: str = "auto"):
        state = self._read_state_memory(repo)
        tx = state.get("current_transaction")
        if tx and tx.get("phase") not in ("committed", "aborted_clean", "rolled_back"):
            print(f"[DRY-RUN WARNING] Production has uncommitted transaction {tx.get('tx_id')} in phase {tx.get('phase')}")
        git_a, git_b = GitAdapter(repo["source"]["local_path"]), GitAdapter(repo["target"]["local_path"])
        binding = compute_endpoint_binding(git_a, git_b, repo)
        epoch = compute_epoch_digest(repo, binding)
        tx_id = generate_tx_id(repo["repo_id"], "DRYRUN")
        scratch = self._scratch_dir("dryrun_" + tx_id + "_")
        try:
            # Any .old decryption bridge writes here, never beneath production .git.
            bridge = WorkspaceMaterializer(git_b, git_b.repo_dir, tx_id=tx_id)
            bridge.staging_dir = os.path.join(scratch, "decrypt")
            os.makedirs(bridge.staging_dir, exist_ok=True)
            tip_a, tip_b = self._tips(repo, git_a, git_b, no_fetch=True)
            policy = ExcludeEngine(repo["manifest"], repo["exclude_rules"])
            self._bootstrap_memory(repo, state, git_a, git_b, tip_a, tip_b, policy, bridge)
            self._validate_pair(policy, git_a, state["last_published_a"], git_b, state["last_published_b"], bridge)
            plan = self._plan(state, git_a, git_b, tip_a, tip_b, requested_direction, repo=repo)
            if plan["state"] == "S0_UP_TO_DATE":
                self._validate_pair(policy, git_a, tip_a, git_b, tip_b, bridge)
                if state.get("last_epoch_digest") not in (None, epoch):
                    print("[DRY-RUN WARNING] Epoch changed; live execution requires baseline revalidation")
                print("[DRY-RUN] S0_UP_TO_DATE; baseline trees validated without writes")
                return plan
            target = git_b if plan["direction"] == "A2B" else git_a
            object_dir = os.path.join(scratch, "target_objects")
            os.makedirs(object_dir)
            git_dir = target._run_checked(["rev-parse", "--git-common-dir"]).decode().strip()
            if not os.path.isabs(git_dir):
                git_dir = os.path.join(target.repo_dir, git_dir)
            env = {"GIT_OBJECT_DIRECTORY": object_dir,
                   "GIT_ALTERNATE_OBJECT_DIRECTORIES": os.path.abspath(os.path.join(git_dir, "objects"))}
            candidate, tree, _ = self._replay(repo, state, plan, git_a, git_b, epoch, env, bridge, policy=policy)
            print(f"[DRY-RUN] {plan['state']}: {len(plan['commits'])} commits; candidate={candidate}; tree={tree}")
            return plan
        finally:
            _safe_rmtree(scratch)

    def _forward_repair(self, tx, materializer, verifier, tx_mgr):
        old_tree, new_tree = tx["pre_tx_tree_target"], tx["final_tree_oid"]
        # If already materialized, do not overwrite a newer worktree just to
        # replay the same bytes. Physical and logical gates still run every time.
        result = verifier.verify_transaction_delta_gates(tx["direction"], old_tree, new_tree)
        try:
            self._gate(result, "Forward repair precheck")
        except TransactionError:
            if tx["direction"] == "B2A":
                repair_id = generate_tx_id(tx_mgr.repo_id, "REPAIR")
                materializer.tx_id = repair_id
                materializer.staging_dir = os.path.join(materializer.target_worktree, ".git", "sync_staging", repair_id)
                info = materializer.prepare_transaction_staging(old_tree, new_tree, direction="B2A", allow_dirty=True)
                def save_lease(lease):
                    tx["executor_lease"] = lease
                    tx_mgr._save_state()
                materializer.materialize_delta_unencrypted_via_old(
                    old_tree, new_tree, staging_info=info, lease_callback=save_lease)
                tx["executor_lease"] = None
                tx_mgr._save_state()
                _safe_rmtree(materializer.staging_dir)
            else:
                materializer.materialize_delta(old_tree, new_tree)
            self._gate(verifier.verify_transaction_delta_gates(tx["direction"], old_tree, new_tree),
                       "Forward repair delta gates")
        self._gate(verifier.verify_logical_integrity(new_tree), "Forward repair logical gate")
        return True

    def _sync_single_repo(self, repo: dict, dry_run: bool = False,
                          requested_direction: str = "auto", no_fetch: bool = False):
        if dry_run:  # Compatibility callers also get the early isolated path.
            return self._sync_single_repo_dry_run(repo, requested_direction)
        git_a, git_b = GitAdapter(repo["source"]["local_path"]), GitAdapter(repo["target"]["local_path"])
        bridge_scratch = self._scratch_dir("live_bridge_")
        try:
            bridge = WorkspaceMaterializer(git_b, git_b.repo_dir, tx_id=generate_tx_id(repo["repo_id"], "BRIDGE"))
            bridge.staging_dir = os.path.join(bridge_scratch, "decrypt")
            return self._sync_live_repo(repo, git_a, git_b, bridge, requested_direction, no_fetch)
        finally:
            _safe_rmtree(bridge_scratch)

    def _sync_live_repo(self, repo, git_a, git_b, bridge, requested_direction, no_fetch):
        binding = compute_endpoint_binding(git_a, git_b, repo)
        epoch = compute_epoch_digest(repo, binding)
        policy = ExcludeEngine(repo["manifest"], repo["exclude_rules"])
        tx_mgr = TransactionManager(repo["repo_id"], self._state_path(repo), git_b, source_git=git_a)
        legacy = repo.get("legacy_state_file", repo["state_file"])
        if not os.path.exists(self._state_path(repo)) and os.path.exists(legacy):
            # Quarantine happens before touching a legacy worktree or remote refs.
            old = self._read_state_memory(repo)
            old_tx = old.get("current_transaction") or {}
            phase = old_tx.get("phase")
            if phase in (None, "committed", "publish_requested"):
                a = old_tx.get("source_tip") if phase == "publish_requested" else old.get("last_published_a")
                b = old_tx.get("candidate_oid") if phase == "publish_requested" else old.get("last_published_b")
                if a and b:
                    self._validate_pair(policy, git_a, a, git_b, b, bridge)
                self._baseline_audit(git_a, git_b, repo=repo)
            tx_mgr.migrate_v22_to_v23(legacy, policy_digest=epoch, endpoint_binding=binding)
        tx = tx_mgr.state.get("current_transaction")
        if tx:
            active = git_b if tx.get("direction", "A2B") == "A2B" else git_a
            direction = tx.get("direction", "A2B")
            mat = WorkspaceMaterializer(active, active.repo_dir, tx_id=tx["tx_id"], direction=direction)
            verifier = DlpVerifier(active, active.repo_dir)
            status = tx_mgr.recover_interrupted_transaction(
                current_policy_digest=epoch, current_endpoint_binding=binding,
                materializer=mat, verifier=verifier,
                forward_repair_fn=lambda recovered: self._forward_repair(recovered, mat, verifier, tx_mgr))
            if status != "none":
                print(f"[+] Recovery: {status}")
        tip_a, tip_b = self._tips(repo, git_a, git_b, no_fetch=no_fetch)
        if not tx_mgr.state.get("last_published_a"):
            self._bootstrap_memory(repo, tx_mgr.state, git_a, git_b, tip_a, tip_b, policy, bridge)
            self._baseline_audit(git_a, git_b, repo=repo)
            tx_mgr.state.update(last_epoch_digest=epoch, endpoint_binding=binding,
                                baseline_physical_audit_epoch=epoch)
            tx_mgr._save_state()
        last_a, last_b = tx_mgr.get_last_published()
        # Every anchor, including S0, must validate B's ENTIRE export tree first.
        self._validate_pair(policy, git_a, last_a, git_b, last_b, bridge)
        plan = self._plan(tx_mgr.state, git_a, git_b, tip_a, tip_b, requested_direction, repo=repo)
        if tx_mgr.state.get("last_epoch_digest") != epoch or tx_mgr.state.get("endpoint_binding") != binding:
            raise RecoveryPolicyMismatchError("Epoch/endpoint changed; explicit full baseline revalidation required")
        if tx_mgr.state.get("baseline_physical_audit_epoch") != epoch:
            self._baseline_audit(git_a, git_b, repo=repo)
            tx_mgr.state["baseline_physical_audit_epoch"] = epoch
            tx_mgr._save_state()
        if plan["state"] == "S0_UP_TO_DATE":
            self._validate_pair(policy, git_a, tip_a, git_b, tip_b, bridge)
            print(f"[+] {repo['repo_id']}: S0_UP_TO_DATE")
            return plan
        return self._execute_plan(repo, tx_mgr, plan, git_a, git_b, tip_a, tip_b, epoch, binding, policy=policy)

    def _execute_plan(self, repo, tx_mgr, plan, git_a, git_b, tip_a, tip_b, epoch, binding, policy=None):
        direction = plan["direction"]
        target = git_b if direction == "A2B" else git_a
        endpoint = repo["target"] if direction == "A2B" else repo["source"]
        branch = self._branch_ref(endpoint)
        expected_remote = tip_b if direction == "A2B" else tip_a
        frozen = tip_a if direction == "A2B" else tip_b
        expected_local = target.rev_parse(branch)
        # A stale target can be repaired only by a separate, audited operation.
        # In particular never silently discard unpublished local commits.
        if target.get_symbolic_head() != branch or expected_local != expected_remote:
            raise TransactionError("Local target branch/HEAD differs from authoritative remote snapshot")
        if target.status_porcelain_z():
            raise TransactionError("Target worktree must be clean, including untracked files")
        tx_id = generate_tx_id(repo["repo_id"], direction)
        old_tree = target.rev_parse(expected_local + "^{tree}")
        # 1: freeze both endpoint and remote snapshots before staging any work.
        tx_mgr.start_transaction(
            tx_id, frozen, policy_digest=epoch, direction=direction, endpoint_binding=binding,
            target_branch_ref=branch, expected_old_target_remote=expected_remote,
            expected_old_target_local=expected_local, pre_tx_tree_target=old_tree)
        materializer = WorkspaceMaterializer(target, target.repo_dir, tx_id=tx_id, direction=direction)
        verifier = DlpVerifier(target, target.repo_dir)
        scratch = self._scratch_dir("bridge_" + tx_id + "_")
        try:
            # 2-4: complete DAG/tree/metadata replay and independent shared gates.
            bridge = WorkspaceMaterializer(git_b, git_b.repo_dir, tx_id=tx_id)
            bridge.staging_dir = os.path.join(scratch, "decrypt")
            candidate, tree, canonical = self._replay(
                repo, tx_mgr.state, plan, git_a, git_b, epoch, bridge=bridge, policy=policy)
            # 5: isolate the candidate and durably prepare ALL backups first.
            tx = tx_mgr.state["current_transaction"]
            target.update_ref(tx["candidate_ref"], candidate)
            info = materializer.prepare_transaction_staging(old_tree, tree, direction=direction)
            tx_mgr.mark_prepared(info["worktree_journal"], candidate, tree, canonical)
            # 6: the materializing barrier precedes even the first worktree write.
            tx_mgr.mark_materializing()
            if direction == "B2A":
                def save_lease(lease):
                    tx["executor_lease"] = lease
                    tx_mgr._save_state()
                materializer.materialize_delta_unencrypted_via_old(
                    old_tree, tree, staging_info=info, lease_callback=save_lease)
            else:
                materializer.materialize_delta(old_tree, tree)
            # 7: fail closed on UNKNOWN as well as FAIL; no ignored DLP result.
            self._gate(verifier.verify_logical_integrity(tree), "Logical integrity gate")
            self._gate(verifier.verify_transaction_delta_gates(direction, old_tree, tree),
                       "Transaction delta gates")
            tx_mgr.mark_verified(candidate, tree, canonical_pending_map=canonical)
            # 8-10: live and recovery share FF proof, exact lease, remote probe,
            # local materialization/ref/index repair, and atomic canonical sealing.
            tx_mgr.mark_publish_requested()
            result = tx_mgr.recover_interrupted_transaction(
                current_policy_digest=epoch, current_endpoint_binding=binding,
                materializer=materializer, verifier=verifier,
                forward_repair_fn=lambda recovered: self._forward_repair(
                    recovered, materializer, verifier, tx_mgr))
            print(f"[+] {repo['repo_id']}: {direction} {result}; candidate={candidate}")
            return plan
        finally:
            _safe_rmtree(scratch)

    def _isolated_rehearsal(self, repo, sandbox_dir, requested_direction, no_fetch):
        sandbox = os.path.abspath(sandbox_dir)
        production = [self.base_dir, repo["source"]["local_path"], repo["target"]["local_path"]]
        for root in production:
            if os.path.commonpath([os.path.realpath(root), os.path.realpath(sandbox)]) == os.path.realpath(root):
                raise ConfigError("Rehearsal sandbox must be outside production directories")
        if os.path.exists(sandbox) and os.listdir(sandbox):
            raise ConfigError("Rehearsal sandbox must be empty (never overwrite an earlier rehearsal)")
        os.makedirs(os.path.join(sandbox, "remotes"), exist_ok=True)
        rebound = copy.deepcopy(repo)
        for label, key in (("a", "source"), ("b", "target")):
            local = os.path.join(sandbox, "repo_" + label)
            remote = os.path.join(sandbox, "remotes", "repo_" + label + ".git")
            shutil.copytree(repo[key]["local_path"], local)
            git = GitAdapter(local)
            # clone --bare from the sandbox copy, never fetch/mutate production.
            git._run_checked(["clone", "--bare", "--no-hardlinks", local, remote])
            git._run_checked(["remote", "set-url", "origin", remote])
            git._run_checked(["remote", "set-url", "--push", "origin", remote])
            rebound[key].update(local_path=local, url=remote)
            branch_ref = self._branch_ref(rebound[key])
            # Seed remote with its frozen authoritative tracking tip rather than
            # assuming a possibly stale local branch is authoritative.
            tracking = "refs/remotes/origin/" + branch_ref[len("refs/heads/"):]
            oid = git.rev_parse(tracking)
            GitAdapter(remote).update_ref(branch_ref, oid)
        a, b = GitAdapter(rebound["source"]["local_path"]), GitAdapter(rebound["target"]["local_path"])
        state = self._read_state_memory(repo)
        binding = compute_endpoint_binding(a, b, rebound)
        epoch = compute_epoch_digest(rebound, binding)
        # Explicitly rebind epochs and revoke all production process references.
        tx = state.get("current_transaction")
        if tx:
            tx["executor_lease"] = None
            tx["endpoint_binding"], tx["epoch_digest"], tx["policy_digest"] = binding, epoch, epoch
            journal = tx.get("worktree_journal")
            def rebase(value):
                if isinstance(value, dict):
                    return {k: rebase(v) for k, v in value.items()}
                if isinstance(value, list):
                    return [rebase(v) for v in value]
                if isinstance(value, str):
                    for key in ("source", "target"):
                        old_path = repo[key]["local_path"]
                        if value == old_path or value.startswith(old_path + os.sep):
                            return rebound[key]["local_path"] + value[len(old_path):]
                return value
            tx["worktree_journal"] = rebase(journal)
        state.update(schema_version="2.3", endpoint_binding=binding, last_epoch_digest=epoch,
                     baseline_physical_audit_epoch=None)
        rebound["state_file"] = rebound["state_file_v23"] = os.path.join(sandbox, "state_v23.json")
        rebound["legacy_state_file"] = os.path.join(sandbox, "legacy_unused.json")
        TransactionManager._durable_replace(rebound["state_file_v23"], json.dumps(state).encode("utf-8"))
        self._sync_single_repo(rebound, requested_direction=requested_direction, no_fetch=no_fetch)

    def lookup_map(self, commit_hash: str, repo_id: Optional[str] = None):
        found = False
        for repo in self.config.repositories:
            if repo_id and repo["repo_id"] != repo_id:
                continue
            state = self._read_state_memory(repo)
            for a, b in state["commit_map"].items():
                if a.startswith(commit_hash):
                    print(f"[+] Repo '{repo['repo_id']}': A {a} -> B {b}")
                    found = True
            for b, commits in state["reverse_map"].items():
                if b.startswith(commit_hash):
                    print(f"[+] Repo '{repo['repo_id']}': B {b} <- A {commits}")
                    found = True
        if not found:
            print(f"[-] Commit hash '{commit_hash}' not found.")

    def show_status(self, repo_id: Optional[str] = None):
        for repo in self.config.repositories:
            if repo_id and repo["repo_id"] != repo_id:
                continue
            state = self._read_state_memory(repo)
            tx = state.get("current_transaction")
            print(f"{repo['repo_id']}: A={state.get('last_published_a')} B={state.get('last_published_b')} "
                  f"phase={tx.get('phase') if tx else None} mappings={len(state['commit_map'])}")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Bidirectional synchronization and DLP security engine")
    subparsers = parser.add_subparsers(dest="command")
    sync_p = subparsers.add_parser("sync", help="Execute incremental bidirectional synchronization")
    sync_p.add_argument("--repo", default=None)
    sync_p.add_argument("--dry-run", action="store_true", help="Object-isolated, zero-production-write planning")
    sync_p.add_argument("--direction", choices=("auto", "a2b", "b2a"), default="auto")
    sync_p.add_argument("--no-fetch", action="store_true", help="Use existing authoritative remote-tracking refs")
    sync_p.add_argument("--isolated-rehearsal", metavar="sandbox_dir", default=None)
    map_p = subparsers.add_parser("map", help="Lookup canonical commit correspondence")
    map_p.add_argument("hash")
    map_p.add_argument("--repo", default=None)
    status_p = subparsers.add_parser("status")
    status_p.add_argument("--repo", default=None)
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return 0
    try:
        app = SyncApp(os.path.dirname(os.path.abspath(__file__)))
        if args.command == "sync":
            return app.run_sync(repo_id=args.repo, dry_run=args.dry_run,
                                requested_direction=args.direction, no_fetch=args.no_fetch,
                                isolated_rehearsal=args.isolated_rehearsal)
        if args.command == "map":
            app.lookup_map(args.hash, repo_id=args.repo)
        else:
            app.show_status(repo_id=args.repo)
        return 0
    except (ConfigError, GitError, TransactionError, DAGEngineError, SanitizerError,
            TreeProjectionError, ReverseProjectionError, MaterializeError, LockBusyError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
