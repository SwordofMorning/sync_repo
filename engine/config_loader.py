"""Configuration and the policy/endpoint epoch shared by planning and recovery."""

import hashlib
import json
import os
from typing import Optional

from engine.content_normalizer import NORMALIZER_SPEC_VERSION
from engine.git_adapter import GitAdapter

DLP_CONTRACT_SPEC_VERSION = "3.0"


class ConfigError(Exception):
    pass


def compute_endpoint_binding(source_git: Optional[GitAdapter],
                             target_git: Optional[GitAdapter], repo_entry: dict) -> dict:
    """Bind both local identities and the actual fetch *and* push destinations.

    None adapters are useful while loading configuration; live callers must pass
    adapters so that an edited git remote cannot reuse a configuration-only epoch.
    Failed remote lookups are deliberately not replaced with configured URLs.
    """
    binding = {}
    for label, key, git in (("a", "source", source_git), ("b", "target", target_git)):
        endpoint = repo_entry[key]
        prefix = "repo_" + label
        branch = endpoint.get("branch", "main")
        binding[prefix + "_local_realpath"] = os.path.normcase(
            os.path.realpath(endpoint["local_path"]))
        binding[prefix + "_fetch_url"] = (
            git.get_remote_url("origin") if git is not None else endpoint.get("url", ""))
        binding[prefix + "_push_url"] = (
            git.get_remote_url("origin", push=True) if git is not None
            else endpoint.get("push_url", endpoint.get("url", "")))
        binding[prefix + "_branch_ref"] = (
            branch if branch.startswith("refs/heads/") else "refs/heads/" + branch)
    return binding


def compute_epoch_digest(repo_entry: dict, endpoint_binding: dict) -> str:
    """Hash the complete, versioned policy and endpoint contract deterministically."""
    payload = {
        "manifest": repo_entry["manifest"],
        "exclude_rules": repo_entry["exclude_rules"],
        "identity_map": repo_entry.get("identity_map", {}),
        "approved_external_identities": sorted(repo_entry.get("approved_external_identities", [])),
        "endpoint_binding": endpoint_binding,
        "NORMALIZER_SPEC_VERSION": NORMALIZER_SPEC_VERSION,
        "DLP_CONTRACT_SPEC_VERSION": DLP_CONTRACT_SPEC_VERSION,
        "message_sanitization_rules": repo_entry.get("message_sanitization_rules", []),
        "default_encryption_extensions": sorted(repo_entry.get("default_encryption_extensions", [])),
    }
    encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False,
                         separators=(",", ":")).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class SyncConfig:
    compute_endpoint_binding = staticmethod(compute_endpoint_binding)
    compute_epoch_digest = staticmethod(compute_epoch_digest)

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
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (ValueError, UnicodeError) as exc:
            raise ConfigError(f"Invalid JSON in {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise ConfigError(f"Configuration must be an object: {path}")
        return data

    def _validate_and_load_repos(self):
        repos_raw = self.raw_data.get("repositories", [])
        if not repos_raw:
            raise ConfigError("No repositories defined in sync_config.json")
        seen_repo_ids, seen_paths = set(), set()
        for item in repos_raw:
            repo_id = item.get("repo_id")
            if not repo_id or not isinstance(repo_id, str) or any(c in repo_id for c in "/\\\x00"):
                raise ConfigError("Missing or unsafe 'repo_id' in repository configuration")
            if repo_id in seen_repo_ids:
                raise ConfigError(f"Duplicate repo_id '{repo_id}' detected")
            seen_repo_ids.add(repo_id)
            endpoints = {}
            for key in ("source", "target"):
                endpoint = dict(item.get(key, {}))
                if not endpoint.get("local_path"):
                    raise ConfigError(f"Missing {key}.local_path for '{repo_id}'")
                local = os.path.abspath(os.path.join(self.base_dir, endpoint["local_path"]))
                identity = os.path.normcase(os.path.realpath(local))
                if identity in seen_paths:
                    raise ConfigError(f"Duplicate repository path '{local}' for repo '{repo_id}'")
                seen_paths.add(identity)
                endpoint.update(local_path=local, branch=endpoint.get("branch", "main"))
                endpoints[key] = endpoint
            manifest_path = os.path.abspath(os.path.join(self.base_dir, item.get("manifest_path", "")))
            exclude_path = os.path.abspath(os.path.join(self.base_dir, item.get("exclude_rules_path", "")))
            state_rel = item.get("state_file", f".sync_state/state_{repo_id}.json")
            state_path = os.path.abspath(os.path.join(self.base_dir, state_rel))
            if state_rel.endswith("_v23.json"):
                v23_path = state_path
                legacy_path = state_path[:-len("_v23.json")] + ".json"
            else:
                legacy_path = state_path
                v23_path = os.path.join(os.path.dirname(state_path), f"state_{repo_id}_v23.json")
            if item.get("state_file_v23"):
                v23_path = os.path.abspath(os.path.join(self.base_dir, item["state_file_v23"]))
            if v23_path == legacy_path:
                raise ConfigError("v2.3 and legacy state files must be physically distinct")
            repo_entry = {
                "repo_id": repo_id,
                "description": item.get("description", ""),
                "enabled": item.get("enabled", True),
                **endpoints,
                "manifest_path": manifest_path,
                "manifest": self._load_json(manifest_path),
                "exclude_rules_path": exclude_path,
                "exclude_rules": self._load_json(exclude_path),
                "state_file": state_path,
                "legacy_state_file": legacy_path,
                "state_file_v23": v23_path,
                "identity_map": self.global_settings.get("identity_map", {}),
                "approved_external_identities": self.global_settings.get("approved_external_identities", []),
                "default_encryption_extensions": self.global_settings.get("default_encryption_extensions", []),
                "legacy_anchor_a_oid": item.get("legacy_anchor_a_oid", ""),
                "legacy_anchor_b_oid": item.get("legacy_anchor_b_oid", ""),
                "history_fold_exceptions": item.get("history_fold_exceptions", []),
                "message_sanitization_rules": item.get("message_sanitization_rules", []),
            }
            binding = compute_endpoint_binding(None, None, repo_entry)
            repo_entry["endpoint_binding"] = binding
            repo_entry["policy_digest"] = compute_epoch_digest(repo_entry, binding)
            repo_entry["epoch_digest"] = repo_entry["policy_digest"]
            self.repositories.append(repo_entry)

    def get_repo(self, repo_id: str) -> dict:
        for repo in self.repositories:
            if repo["repo_id"] == repo_id:
                return repo
        raise ConfigError(f"Repository '{repo_id}' not found in configuration")
