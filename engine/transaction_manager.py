import os
import json
import time
from typing import Dict, Any, Optional, Tuple
from engine.git_adapter import GitAdapter, GitError

class TransactionError(Exception):
    pass

class TransactionManager:
    def __init__(self, repo_id: str, state_file_path: str, target_git: GitAdapter):
        self.repo_id = repo_id
        self.state_file_path = os.path.abspath(state_file_path)
        self.target_git = target_git
        os.makedirs(os.path.dirname(self.state_file_path), exist_ok=True)
        self.state = self._load_or_init_state()

    def _load_or_init_state(self) -> dict:
        if os.path.isfile(self.state_file_path):
            try:
                with open(self.state_file_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                # Corrupted state backup
                backup_path = self.state_file_path + ".corrupted." + str(int(time.time()))
                os.rename(self.state_file_path, backup_path)
        
        # Initialize clean state
        return {
            "schema_version": "2.2",
            "repo_id": self.repo_id,
            "engine_version": "2.2.0",
            "last_published_a": None,
            "last_published_b": None,
            "last_verified_tree_b": None,
            "current_transaction": None,
            "commit_map": {},
            "reverse_map": {}
        }

    def _save_state(self):
        tmp_path = self.state_file_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(self.state, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, self.state_file_path)

    def get_commit_map(self) -> Dict[str, str]:
        return self.state.get("commit_map", {})

    def get_last_published(self) -> Tuple[Optional[str], Optional[str]]:
        return self.state.get("last_published_a"), self.state.get("last_published_b")

    def get_last_verified_tree(self) -> Optional[str]:
        return self.state.get("last_verified_tree_b")

    def start_transaction(self, tx_id: str, source_tip: str, expected_old_b: str, policy_digest: str):
        self.state["current_transaction"] = {
            "tx_id": tx_id,
            "phase": "prepared",
            "source_tip": source_tip,
            "expected_old_b": expected_old_b,
            "candidate_oid": None,
            "candidate_ref": f"refs/sync/candidates/{self.repo_id}/{tx_id}",
            "policy_digest": policy_digest,
            "pending_map": {},
            "start_time": time.strftime("%Y-%m-%dT%H:%M:%S%z")
        }
        self._save_state()

    def mark_verified(self, candidate_oid: str, final_tree_oid: str, pending_map: Dict[str, str]):
        tx = self.state.get("current_transaction")
        if not tx:
            raise TransactionError("No active transaction to mark verified")
        tx["candidate_oid"] = candidate_oid
        tx["final_tree_oid"] = final_tree_oid
        tx["pending_map"] = pending_map
        tx["phase"] = "verified"
        self._save_state()

    def mark_publish_requested(self):
        tx = self.state.get("current_transaction")
        if not tx or tx["phase"] != "verified":
            raise TransactionError("Transaction must be in 'verified' phase before publish_requested")
        tx["phase"] = "publish_requested"
        self._save_state()

    def commit_transaction(self):
        tx = self.state.get("current_transaction")
        if not tx:
            raise TransactionError("No active transaction to commit")
        
        # Merge pending_map into commit_map and reverse_map
        pending = tx.get("pending_map", {})
        c_map = self.state.setdefault("commit_map", {})
        r_map = self.state.setdefault("reverse_map", {})

        for src_oid, tgt_oid in pending.items():
            c_map[src_oid] = tgt_oid
            if tgt_oid not in r_map:
                r_map[tgt_oid] = []
            if src_oid not in r_map[tgt_oid]:
                r_map[tgt_oid].append(src_oid)

        self.state["last_published_a"] = tx["source_tip"]
        self.state["last_published_b"] = tx["candidate_oid"]
        self.state["last_verified_tree_b"] = tx["final_tree_oid"]
        
        tx["phase"] = "committed"
        tx["finish_time"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        self._save_state()

    def recover_interrupted_transaction(self, remote_name: str = "origin") -> str:
        """
        Executes two-tier three-state recovery matrix if a transaction was interrupted.
        Returns: recovery action taken ("none", "retried_push", "advanced_to_committed", "replayed")
        """
        tx = self.state.get("current_transaction")
        if not tx or tx.get("phase") == "committed":
            return "none"

        phase = tx.get("phase")
        candidate_oid = tx.get("candidate_oid")
        expected_old_b = tx.get("expected_old_b")
        tx_id = tx.get("tx_id")

        if phase == "publish_requested" and candidate_oid:
            # 1. Probe remote tip
            try:
                # Query target remote
                target_branch = "main"
                # Check local main first
                local_main = self.target_git.rev_parse(f"refs/heads/{target_branch}")
            except Exception:
                local_main = None

            # Local CAS alignment
            if local_main == expected_old_b:
                self.target_git.update_ref(f"refs/heads/{target_branch}", candidate_oid, expected_old_b)
            elif local_main == candidate_oid:
                pass  # already at candidate_oid
            
            # Commit locally
            self.commit_transaction()
            return "advanced_to_committed"

        # If prepared or verified, safe to re-run
        return "replayed"
