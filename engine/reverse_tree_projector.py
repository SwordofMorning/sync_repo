from typing import Callable, Dict, List, Optional, Set, Tuple

from engine.content_normalizer import ContentNormalizer, TSD_MAGIC_HEADER
from engine.exclude_engine import ExcludeDecision, ExcludeEngine
from engine.git_adapter import GitAdapter
from engine.path_validator import (
    ALLOWED_SHARED_BLOB_MODES,
    CaseFoldedNamespaceTrie,
    NamespaceCollisionError,
    PathValidationError,
    collect_ancestor_dirs,
    validate_platform_rel_path,
)


class ReverseProjectionError(Exception):
    pass


class _TargetObjectView:
    """Expose ephemeral A objects to policy readers without changing process env."""

    def __init__(self, git: GitAdapter, env: Optional[dict]):
        self.git, self.env = git, env

    def ls_tree_r_z(self, tree_oid: str) -> List[dict]:
        return self.git.ls_tree_r_z(tree_oid, env=self.env)

    def ls_tree_r_z_strict(self, tree_oid: str) -> List[dict]:
        return self.git.ls_tree_r_z_strict(tree_oid, env=self.env)

    def cat_file_blob(self, oid: str) -> bytes:
        return self.git.cat_file_blob(oid, env=self.env)


class ReverseTreeProjector:
    def __init__(
        self,
        git_a: GitAdapter,
        git_b: GitAdapter,
        exclude_engine: ExcludeEngine,
        dlp_bridge=None,
        normalizer: Optional[ContentNormalizer] = None,
        target_env_a: Optional[dict] = None,
    ):
        self.git_a = git_a
        self.git_b = git_b
        self.exclude_engine = exclude_engine
        self.dlp_bridge = dlp_bridge
        self.normalizer = normalizer if normalizer is not None else ContentNormalizer()
        self.target_env_a = dict(target_env_a) if target_env_a is not None else None
        self._target_view = _TargetObjectView(self.git_a, self.target_env_a)

    def compute_private_complement(
        self, tree_oid_a: str
    ) -> Tuple[Dict[str, Tuple[str, str, str]], Set[str]]:
        """Return all non-ALLOW leaves (mode, type, OID) and their ancestors.

        Even historical BLOCK_REVIEW assets belong to the non-shared complement:
        they must never be overwritten, exported, or silently dropped by an overlay.
        Private paths are deliberately not subjected to shared-platform validation.
        """
        p_priv: Dict[str, Tuple[str, str, str]] = {}
        a_priv: Set[str] = set()
        seen: Set[str] = set()
        for entry in self.git_a.ls_tree_r_z_strict(tree_oid_a, env=self.target_env_a):
            path, mode = entry["path"], entry["mode"]
            if path in seen:
                raise ReverseProjectionError(f"Duplicate A tree entry: '{path}'")
            seen.add(path)
            decision, _, _ = self.exclude_engine.evaluate_effective_path(
                path, mode=mode, is_tree=False
            )
            if decision in (ExcludeDecision.PRUNE, ExcludeDecision.BLOCK_REVIEW):
                p_priv[path] = (mode, entry["type"], entry["oid"])
                a_priv.update(collect_ancestor_dirs(path))
            elif decision != ExcludeDecision.ALLOW:
                raise ReverseProjectionError(f"Unknown policy decision at '{path}': {decision}")
        return p_priv, a_priv

    def _check_shared_path(self, path: str, mode: str, entry_type: str = "blob") -> None:
        try:
            validate_platform_rel_path(path)
        except PathValidationError as exc:
            raise ReverseProjectionError(str(exc)) from exc
        decision, rule_id, reason = self.exclude_engine.evaluate_effective_path(
            path, mode=mode, is_tree=False
        )
        if decision != ExcludeDecision.ALLOW:
            raise ReverseProjectionError(f"Non-exportable path '{path}' ({rule_id}): {reason}")
        if (mode not in ALLOWED_SHARED_BLOB_MODES and mode != "120000") or entry_type != "blob":
            raise ReverseProjectionError(f"Unsupported shared entry at '{path}': {mode} {entry_type}")

    def _decrypt_blob(self, raw_bytes: bytes, path: str, oid: str) -> bytes:
        if self.dlp_bridge is None:
            if raw_bytes.startswith(TSD_MAGIC_HEADER):
                raise ReverseProjectionError(f"Ciphertext at '{path}' requires an approved DLP bridge")
            plain_bytes = raw_bytes
        elif callable(getattr(self.dlp_bridge, "decrypt_blob_via_old_channel", None)):
            plain_bytes = self.dlp_bridge.decrypt_blob_via_old_channel(
                raw_bytes, expected_source_oid=oid, hint_path=path
            )
        elif callable(self.dlp_bridge):
            plain_bytes = self.dlp_bridge(raw_bytes, path)
        else:
            raise ReverseProjectionError("DLP bridge is neither callable nor an approved blob reader")
        if not isinstance(plain_bytes, bytes) or plain_bytes.startswith(TSD_MAGIC_HEADER):
            raise ReverseProjectionError(f"DLP bridge did not return plaintext bytes for '{path}'")
        return plain_bytes

    def _export_decryptor(self, entries_b: List[dict]) -> Callable[[bytes], bytes]:
        """Bind the policy API's one-argument decrypt callback to immutable B OIDs.

        Decryption is content-addressed; a path is only a hint. Reading raw blobs
        here has no target-side effects, and policy validation precedes decryption.
        """
        raw_by_oid: Dict[str, bytes] = {}
        bindings: Dict[bytes, Tuple[str, str]] = {}
        for entry in entries_b:
            if entry["type"] != "blob":
                continue
            oid = entry["oid"]
            if oid not in raw_by_oid:
                raw_by_oid[oid] = self.git_b.cat_file_blob(oid)
            bindings.setdefault(raw_by_oid[oid], (entry["path"], oid))
        plain_by_raw: Dict[bytes, bytes] = {}

        def decrypt_fn(raw_bytes: bytes) -> bytes:
            if raw_bytes not in bindings:
                raise ReverseProjectionError("Export validator requested a blob outside the selected B tree")
            if raw_bytes not in plain_by_raw:
                path, oid = bindings[raw_bytes]
                plain_by_raw[raw_bytes] = self._decrypt_blob(raw_bytes, path, oid)
            return plain_by_raw[raw_bytes]

        return decrypt_fn

    @staticmethod
    def _index_entries(entries: List[dict]) -> Dict[str, Tuple[str, str, str]]:
        indexed: Dict[str, Tuple[str, str, str]] = {}
        for entry in entries:
            path = entry["path"]
            if path in indexed:
                raise ReverseProjectionError(f"Duplicate tree path '{path}'")
            indexed[path] = (entry["mode"], entry["type"], entry["oid"])
        return indexed

    def _verify_overlay_namespace(
        self,
        entries_a: Dict[str, Tuple[str, str, str]],
        p_priv: Dict[str, Tuple[str, str, str]],
    ) -> None:
        trie = CaseFoldedNamespaceTrie()
        try:
            for path in p_priv:
                trie.insert_path(path, origin_tag="PRIVATE")
            for path, (mode, entry_type, _) in entries_a.items():
                if path not in p_priv:
                    self._check_shared_path(path, mode, entry_type)
                    trie.insert_path(path, origin_tag="SHARED")
        except NamespaceCollisionError as exc:
            raise ReverseProjectionError(f"Private/shared namespace collision: {exc}") from exc

    def project_reverse_commit_tree(
        self, parent_commit_a: str, parent_commit_b: str, commit_b: str
    ) -> Tuple[str, Dict[str, bytes]]:
        """Overlay one linear B delta while preserving A's entire private complement.

        Only objects are written; refs, the index, and the worktree are untouched.
        All delta permissions, plaintext, and namespace checks precede target writes.
        """
        parents_b = self.git_b.get_commit_parents(commit_b)
        if parents_b != [parent_commit_b]:
            raise ReverseProjectionError(
                f"NON_LINEAR_TOPOLOGY_HALT: {commit_b} parents {parents_b!r} "
                f"do not equal [{parent_commit_b!r}]"
            )
        base_tree_a = self.git_a.rev_parse(f"{parent_commit_a}^{{tree}}", env=self.target_env_a)
        old_tree_b = self.git_b.rev_parse(f"{parent_commit_b}^{{tree}}")
        new_tree_b = self.git_b.rev_parse(f"{commit_b}^{{tree}}")
        entries_b = self.git_b.ls_tree_r_z_strict(new_tree_b)
        for entry in entries_b:
            self._check_shared_path(entry["path"], entry["mode"], entry["type"])
        decrypt_fn = self._export_decryptor(entries_b)
        passed, details = self.exclude_engine.validate_export_tree(
            self.git_b, new_tree_b, decrypt_fn=decrypt_fn
        )
        if not passed:
            raise ReverseProjectionError(f"Invalid Repo B export tree: {details}")
        # The export validator scans its configured scope; independently reject
        # undecryptable ciphertext even outside that scope.
        for entry in entries_b:
            decrypt_fn(self.git_b.cat_file_blob(entry["oid"]))

        p_priv_base, a_priv_base = self.compute_private_complement(base_tree_a)
        entries_a = self._index_entries(
            self.git_a.ls_tree_r_z_strict(base_tree_a, env=self.target_env_a)
        )
        staged_plain_blobs: Dict[str, bytes] = {}
        seen_delta: Set[str] = set()
        for delta in self.git_b.diff_tree_raw_strict(old_tree_b, new_tree_b):
            path, status = delta["path"], delta["status"]
            if path in seen_delta:
                raise ReverseProjectionError(f"Duplicate delta path '{path}'")
            seen_delta.add(path)
            if status not in {"A", "M", "D", "T"}:
                raise ReverseProjectionError(f"Unsupported delta status '{status}' at '{path}'")
            mode = delta["old_mode"] if status == "D" else delta["new_mode"]
            self._check_shared_path(path, mode)
            if (
                path in p_priv_base or path in a_priv_base
                or any(anc in p_priv_base for anc in collect_ancestor_dirs(path))
            ):
                raise ReverseProjectionError(f"Delta at '{path}' would touch a private asset or its ancestor")
            previous = entries_a.get(path)
            if status == "A" and previous is not None:
                raise ReverseProjectionError(f"Added B path '{path}' already exists in A; invalid anchor")
            if status != "A" and previous is None:
                raise ReverseProjectionError(f"Changed B path '{path}' is absent in A; invalid anchor")
            if status == "D":
                del entries_a[path]
                continue
            if previous is not None:
                self._check_shared_path(path, previous[0], previous[1])
            raw_bytes = self.git_b.cat_file_blob(delta["new_oid"])
            plain_bytes = self._decrypt_blob(raw_bytes, path, delta["new_oid"])
            baseline_bytes_a = (
                self.git_a.cat_file_blob(previous[2], env=self.target_env_a)
                if previous is not None else None
            )
            canon_bytes = self.normalizer.normalize_for_repo_a(path, plain_bytes, baseline_bytes_a)
            if not isinstance(canon_bytes, bytes) or canon_bytes.startswith(TSD_MAGIC_HEADER):
                raise ReverseProjectionError(f"Normalization left ciphertext at '{path}'")
            passed, rule_id, hint = self.exclude_engine.scan_content_blob(path, canon_bytes)
            if not passed:
                self.exclude_engine.record_audit(
                    commit_b, path, ExcludeDecision.BLOCK_REVIEW,
                    rule_id or "CONTENT_SCAN_FAILED", hint or "",
                )
                raise ReverseProjectionError(f"Content scan blocked '{path}' ({rule_id}): {hint}")
            staged_plain_blobs[path] = canon_bytes
            entries_a[path] = (mode, "blob", delta["new_oid"])

        self._verify_overlay_namespace(entries_a, p_priv_base)
        for path, canon_bytes in staged_plain_blobs.items():
            mode, entry_type, _ = entries_a[path]
            entries_a[path] = (
                mode, entry_type, self.git_a.hash_object_write(canon_bytes, env=self.target_env_a)
            )
        new_tree_a = self._build_tree_strict(entries_a)
        p_priv_after, a_priv_after = self.compute_private_complement(new_tree_a)
        if p_priv_after != p_priv_base or a_priv_after != a_priv_base:
            raise ReverseProjectionError("Private complement changed during reverse projection")
        shared_a = self.exclude_engine.compute_shared_norm(
            self._target_view if self.target_env_a is not None else self.git_a,
            new_tree_a, normalizer=self.normalizer,
        )
        shared_b = self.exclude_engine.compute_shared_norm(
            self.git_b, new_tree_b, normalizer=self.normalizer, decrypt_fn=decrypt_fn,
        )
        if shared_a != shared_b:
            raise ReverseProjectionError("Reverse candidate SharedNorm does not match the complete Repo B tree")
        return new_tree_a, staged_plain_blobs

    def _build_tree_strict(self, entries_a: Dict[str, Tuple[str, str, str]]) -> str:
        """Construct a Git tree without ever replacing a directory by a leaf.

        No platform validation is applied to preserved PRIVATE leaves here: old
        A-only names/modes must round-trip byte-for-byte. Shared entries have
        already passed validation, and the trie also checks private/shared aliases.
        """
        root: dict = {}
        trie = CaseFoldedNamespaceTrie()
        for path, entry in entries_a.items():
            try:
                trie.insert_path(path, origin_tag="TREE")
            except NamespaceCollisionError as exc:
                raise ReverseProjectionError(f"Tree namespace collision: {exc}") from exc
            if not isinstance(entry, tuple) or len(entry) != 3:
                raise ReverseProjectionError(f"Invalid tree leaf at '{path}'")
            mode, entry_type, _ = entry
            if entry_type not in {"blob", "commit"} or mode.startswith("04"):
                raise ReverseProjectionError(f"Non-leaf tree entry at '{path}'")
            parts = path.split("/")
            cur = root
            for part in parts[:-1]:
                if part not in cur:
                    cur[part] = {}
                elif not isinstance(cur[part], dict):
                    raise ReverseProjectionError(f"Leaf/directory overwrite at '{path}'")
                cur = cur[part]
            if parts[-1] in cur:
                raise ReverseProjectionError(f"Directory/leaf overwrite at '{path}'")
            cur[parts[-1]] = entry

        def write_subtree(node: dict) -> str:
            records: List[Tuple[str, str, str, str]] = []
            for name, child in node.items():
                if isinstance(child, dict):
                    records.append(("040000", "tree", write_subtree(child), name))
                else:
                    mode, entry_type, oid = child
                    records.append((mode, entry_type, oid, name))
            return self.git_a.mktree_z(records, env=self.target_env_a)

        return write_subtree(root)
