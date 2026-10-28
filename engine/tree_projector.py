from typing import Dict, Iterable, List, Optional, Set, Tuple

from engine.content_normalizer import ContentNormalizer
from engine.exclude_engine import ExcludeDecision, ExcludeEngine
from engine.git_adapter import GitAdapter
from engine.path_validator import (
    ALLOWED_SHARED_BLOB_MODES,
    CaseFoldedNamespaceTrie,
    NamespaceCollisionError,
    PathValidationError,
    validate_platform_rel_path,
)


class TreeProjectionError(Exception):
    pass


class SecurityBlockError(TreeProjectionError):
    pass


class TreeProjector:
    def __init__(
        self,
        source_git: GitAdapter,
        target_git: GitAdapter,
        exclude_engine: ExcludeEngine,
        policy_digest: str = "default",
        normalizer: Optional[ContentNormalizer] = None,
        target_env: Optional[dict] = None,
    ):
        self.source_git = source_git
        self.target_git = target_git
        self.exclude_engine = exclude_engine
        self.policy_digest = policy_digest
        self.normalizer = normalizer if normalizer is not None else ContentNormalizer()
        self.target_env = dict(target_env) if target_env is not None else None
        # Retained for legacy callers; the compatibility pre-check never imports objects.
        self.objects_streamed = False
        self._subtree_cache: Dict[Tuple[str, str, str], Optional[str]] = {}
        self._preflight_cache: Dict[Tuple[str, str, str], Tuple[str, ...]] = {}
        self._blob_cache: Dict[Tuple[str, str], str] = {}
        self._ls_tree_cache: Dict[str, List[dict]] = {}
        self._blob_bytes_cache: Dict[str, bytes] = {}
        self._verified_scans: Set[Tuple[str, str, str]] = set()
        self._audited_decisions: Set[Tuple[str, str, str, str]] = set()
        self._projection_depth = 0
        self._baseline_seeded = False

    def seed_from_baseline(self, base_commit_a: str, base_commit_b: str) -> None:
        """
        Pre-seeds _subtree_cache, _preflight_cache, and _blob_cache from a verified
        baseline pair (base_commit_a, base_commit_b) for all directories and blobs
        whose Git OID in A equals their Git OID in B.
        """
        self._baseline_seeded = True
        raw_a = self.source_git._run_checked(["ls-tree", "-d", "-r", "-z", base_commit_a])
        raw_b = self.target_git._run_checked(["ls-tree", "-d", "-r", "-z", base_commit_b])
        dirs_a = {}
        for chunk in raw_a.split(b"\0"):
            if chunk:
                meta, p = chunk.split(b"\t", 1)
                dirs_a[p.decode("utf-8", "strict")] = meta.decode("ascii").split()[2]
        for chunk in raw_b.split(b"\0"):
            if chunk:
                meta, p = chunk.split(b"\t", 1)
                rel_dir = p.decode("utf-8", "strict")
                oid_b = meta.decode("ascii").split()[2]
                if dirs_a.get(rel_dir) == oid_b:
                    key = (rel_dir, oid_b, self.policy_digest)
                    self._subtree_cache[key] = oid_b
                    self._preflight_cache[key] = (rel_dir,)
        for entry in self.target_git.ls_tree_r_z_strict(base_commit_b):
            p, oid = entry["path"], entry["oid"]
            self._blob_cache[(p, oid)] = oid
            self._verified_scans.add((p, oid, self.policy_digest))

    def _audit_decision(
        self, commit_oid: str, path: str, decision: str, rule_id: str, reason: Optional[str]
    ) -> None:
        key = (commit_oid, path, decision, rule_id)
        if key not in self._audited_decisions:
            self.exclude_engine.record_audit(commit_oid, path, decision, rule_id, reason or "")
            self._audited_decisions.add(key)

    def _check_entry(self, commit_oid: str, child_path: str, entry: dict) -> str:
        mode_str, type_str = entry["mode"], entry["type"]
        decision, rule_id, reason = self.exclude_engine.evaluate_effective_path(
            child_path, mode=mode_str, is_tree=(type_str == "tree")
        )
        if decision in (ExcludeDecision.PRUNE, ExcludeDecision.BLOCK_REVIEW):
            self._audit_decision(commit_oid, child_path, decision, rule_id, reason)
            if decision == ExcludeDecision.BLOCK_REVIEW:
                raise SecurityBlockError(f"Blocked '{child_path}' ({rule_id}): {reason}")
            return decision
        if decision != ExcludeDecision.ALLOW:
            raise SecurityBlockError(f"Unknown policy decision for '{child_path}': {decision}")

        try:
            validate_platform_rel_path(child_path)
        except PathValidationError as exc:
            self._audit_decision(
                commit_oid, child_path, ExcludeDecision.BLOCK_REVIEW,
                "INVALID_PLATFORM_PATH", str(exc),
            )
            raise SecurityBlockError(str(exc)) from exc
        if not (
            (type_str == "tree" and mode_str == "040000")
            or (type_str == "blob" and (mode_str in ALLOWED_SHARED_BLOB_MODES or mode_str == "120000"))
        ):
            self._audit_decision(
                commit_oid, child_path, ExcludeDecision.BLOCK_REVIEW,
                "UNSUPPORTED_SHARED_GIT_MODE", f"Unsupported {mode_str} {type_str}",
            )
            raise SecurityBlockError(
                f"Unsupported shared Git entry at '{child_path}': {mode_str} {type_str}"
            )
        return decision

    def _ls_source_tree(self, src_tree_oid: str) -> List[dict]:
        if src_tree_oid not in self._ls_tree_cache:
            self._ls_tree_cache[src_tree_oid] = self.source_git.ls_tree_z(src_tree_oid)
        return self._ls_tree_cache[src_tree_oid]

    def _verify_and_scan_blob(self, commit_oid: str, child_path: str, oid_str: str) -> bytes:
        if oid_str not in self._blob_bytes_cache:
            self._blob_bytes_cache[oid_str] = self.source_git.cat_file_blob(oid_str)
        blob_bytes = self._blob_bytes_cache[oid_str]
        key = (child_path, oid_str, self.policy_digest)
        if (
            self.exclude_engine.is_path_in_content_scan_scope(child_path)
            and key not in self._verified_scans
        ):
            passed, rule_id, hint = self.exclude_engine.scan_content_blob(child_path, blob_bytes)
            if not passed:
                self._audit_decision(
                    commit_oid, child_path, ExcludeDecision.BLOCK_REVIEW,
                    rule_id or "CONTENT_SCAN_FAILED", hint,
                )
                raise SecurityBlockError(
                    f"Content scan blocked '{child_path}' ({rule_id}): {hint}"
                )
            self._verified_scans.add(key)
        return blob_bytes

    def _preflight_subtree(
        self, commit_oid: str, rel_dir: str, src_tree_oid: str
    ) -> Tuple[str, ...]:
        """Read-only authorization of the entire subtree, including historical blobs."""
        key = (rel_dir, src_tree_oid, self.policy_digest)
        if key in self._preflight_cache:
            return self._preflight_cache[key]
        paths: List[str] = []
        # ls_tree_z uses checked Git I/O and strict UTF-8. Failures are never cached.
        for entry in self._ls_source_tree(src_tree_oid):
            child_path = f"{rel_dir}/{entry['name']}" if rel_dir else entry["name"]
            if self._check_entry(commit_oid, child_path, entry) == ExcludeDecision.PRUNE:
                continue
            if entry["type"] == "tree":
                paths.extend(self._preflight_subtree(commit_oid, child_path, entry["oid"]))
            else:
                if (child_path, entry["oid"], self.policy_digest) not in self._verified_scans:
                    self._verify_and_scan_blob(commit_oid, child_path, entry["oid"])
                paths.append(child_path)
        result = tuple(paths)
        self._preflight_cache[key] = result
        return result

    @staticmethod
    def _verify_namespace(paths: Iterable[str]) -> None:
        trie = CaseFoldedNamespaceTrie()
        try:
            for path in paths:
                trie.insert_path(path, origin_tag="SHARED")
        except NamespaceCollisionError as exc:
            raise SecurityBlockError(f"Projected namespace is not representable: {exc}") from exc

    def stream_approved_objects(self, base_commit: str, tip_commit: str) -> None:
        """Compatibility entry point: pre-check the range without copying any closure.

        Every pending snapshot is checked, so a leak introduced and subsequently
        removed in this range is still rejected. No commits, raw source trees, or
        unapproved blobs are ever packed/imported by this method.
        """
        for commit_oid in self.source_git.rev_list_topo(base_commit, tip_commit):
            tree_oid = self.source_git.rev_parse(f"{commit_oid}^{{tree}}")
            self._verify_namespace(self._preflight_subtree(commit_oid, "", tree_oid))
        self.objects_streamed = True

    def project_commit_tree(self, commit_oid: str) -> str:
        """Project a complete source snapshot, independent of the changed-path set."""
        self._ls_tree_cache.clear()
        src_tree_oid = self.source_git.rev_parse(f"{commit_oid}^{{tree}}")
        projected_root_tree_oid = self._project_subtree(commit_oid, "", src_tree_oid)
        if projected_root_tree_oid is None:
            raise TreeProjectionError("Root projection unexpectedly omitted the root tree")
        if not self._baseline_seeded:
            self._verify_namespace(
                entry["path"] for entry in self.target_git.ls_tree_r_z_strict(
                    projected_root_tree_oid, env=self.target_env
                )
            )
        return projected_root_tree_oid

    def _project_subtree(
        self, commit_oid: str, rel_dir: str, src_tree_oid: str
    ) -> Optional[str]:
        """Recursively rebuild only approved entries, memoized by path and policy.

        Preflight precedes the first target write, including when this helper is
        called directly. Thus a later BLOCK_REVIEW/content failure cannot leave
        even an earlier approved object imported by this projection attempt.
        """
        if self._projection_depth == 0:
            self._verify_namespace(self._preflight_subtree(commit_oid, rel_dir, src_tree_oid))
        key = (rel_dir, src_tree_oid, self.policy_digest)
        if key in self._subtree_cache:
            return self._subtree_cache[key]

        records: List[Tuple[str, str, str, str]] = []
        self._projection_depth += 1
        try:
            for entry in self._ls_source_tree(src_tree_oid):
                name = entry["name"]
                child_path = f"{rel_dir}/{name}" if rel_dir else name
                mode_str, type_str, oid_str = entry["mode"], entry["type"], entry["oid"]
                if self._check_entry(commit_oid, child_path, entry) == ExcludeDecision.PRUNE:
                    continue
                if type_str == "tree":
                    projected_oid = self._project_subtree(commit_oid, child_path, oid_str)
                    if projected_oid is not None:
                        records.append((mode_str, type_str, projected_oid, name))
                else:
                    blob_key = (child_path, oid_str)
                    if blob_key in self._blob_cache:
                        approved_oid = self._blob_cache[blob_key]
                    else:
                        blob_bytes = self._verify_and_scan_blob(commit_oid, child_path, oid_str)
                        canon_bytes = (
                            blob_bytes
                            if mode_str == "120000"
                            else self.normalizer.normalize_for_git_store("A2B", child_path, blob_bytes)
                        )
                        # Write this approved blob alone. Never import its source
                        # tree/commit closure, even if mktree reports a missing object.
                        approved_oid = self.target_git.hash_object_write(
                            canon_bytes, env=self.target_env
                        )
                        self._blob_cache[blob_key] = approved_oid
                    records.append((mode_str, type_str, approved_oid, name))
            projected_oid = (
                self.target_git.mktree_z(records, env=self.target_env)
                if records or not rel_dir else None
            )
            self._subtree_cache[key] = projected_oid
            return projected_oid
        finally:
            self._projection_depth -= 1
