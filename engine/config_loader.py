import os
import json
import hashlib
from typing import Dict, Any, List

class ConfigError(Exception):
    pass

class SyncConfig:
    def __init__(self, base_dir: str, config_path: str = None):
        self.base_dir = os.path.abspath(base_dir)
        if config_path is None:
            config_path = os.path.join(self.base_dir, "configs", "sync_config.json")
        self.config_path = os.path.abspath(config_path)
        self.raw_data = self._load_json(self.config_path)
        self.global_settings = self.raw_data.get("global_settings", {})
        self.repositories = []
        self._validate_and_load_repos()

    def _load_json(self, path: str) -> dict:
        if not os.path.isfile(path):
            raise ConfigError(f"Configuration file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError as e:
                raise ConfigError(f"Invalid JSON in {path}: {e}")

    def _validate_and_load_repos(self):
        repos_raw = self.raw_data.get("repositories", [])
        if not repos_raw:
            raise ConfigError("No repositories defined in sync_config.json")
        
        seen_repo_ids = set()
        seen_source_paths = set()
        seen_target_paths = set()
        
        for item in repos_raw:
            repo_id = item.get("repo_id")
            if not repo_id:
                raise ConfigError("Missing 'repo_id' in repository configuration")
            if repo_id in seen_repo_ids:
                raise ConfigError(f"Duplicate repo_id '{repo_id}' detected")
            seen_repo_ids.add(repo_id)
            
            source = item.get("source", {})
            target = item.get("target", {})
            
            source_local = os.path.abspath(os.path.join(self.base_dir, source.get("local_path", "")))
            target_local = os.path.abspath(os.path.join(self.base_dir, target.get("local_path", "")))
            
            if source_local in seen_source_paths:
                raise ConfigError(f"Duplicate source path '{source_local}' for repo '{repo_id}'")
            if target_local in seen_target_paths:
                raise ConfigError(f"Duplicate target path '{target_local}' for repo '{repo_id}'")
            if source_local == target_local:
                raise ConfigError(f"Source and target paths cannot be identical for repo '{repo_id}'")
            
            seen_source_paths.add(source_local)
            seen_target_paths.add(target_local)
            
            # Resolve manifest and exclude files
            manifest_rel = item.get("manifest_path", "")
            manifest_path = os.path.abspath(os.path.join(self.base_dir, manifest_rel))
            manifest_data = self._load_json(manifest_path)
            
            exclude_rel = item.get("exclude_rules_path", "")
            exclude_path = os.path.abspath(os.path.join(self.base_dir, exclude_rel))
            exclude_data = self._load_json(exclude_path)
            
            state_rel = item.get("state_file", f".sync_state/state_{repo_id}.json")
            state_path = os.path.abspath(os.path.join(self.base_dir, state_rel))
            
            # Calculate policy digest for this repository
            policy_bytes = (
                json.dumps(manifest_data, sort_keys=True) +
                json.dumps(exclude_data, sort_keys=True) +
                json.dumps(self.global_settings.get("identity_map", {}), sort_keys=True)
            ).encode("utf-8")
            policy_digest = "sha256:" + hashlib.sha256(policy_bytes).hexdigest()
            
            repo_entry = {
                "repo_id": repo_id,
                "description": item.get("description", ""),
                "enabled": item.get("enabled", True),
                "source": {
                    "alias": source.get("alias", ""),
                    "url": source.get("url", ""),
                    "local_path": source_local,
                    "branch": source.get("branch", "main")
                },
                "target": {
                    "alias": target.get("alias", ""),
                    "url": target.get("url", ""),
                    "local_path": target_local,
                    "branch": target.get("branch", "main")
                },
                "manifest_path": manifest_path,
                "manifest": manifest_data,
                "exclude_rules_path": exclude_path,
                "exclude_rules": exclude_data,
                "state_file": state_path,
                "policy_digest": policy_digest,
                "legacy_anchor_b_oid": item.get("legacy_anchor_b_oid", ""),
                "history_fold_exceptions": item.get("history_fold_exceptions", []),
                "message_sanitization_rules": item.get("message_sanitization_rules", [])
            }
            self.repositories.append(repo_entry)

    def get_repo(self, repo_id: str) -> dict:
        for r in self.repositories:
            if r["repo_id"] == repo_id:
                return r
        raise ConfigError(f"Repository '{repo_id}' not found in configuration")
