import fnmatch
import re
from typing import Callable, Dict, List, Optional, Set, Tuple

from engine.content_normalizer import ContentNormalizer
from engine.path_validator import (
    ALLOWED_SHARED_BLOB_MODES,
    ALLOWED_SHARED_MODES,
    CaseFoldedNamespaceTrie,
    NamespaceCollisionError,
    PathValidationError,
    collect_ancestor_dirs,
    validate_platform_rel_path,
)


class ExportTreeComplianceError(Exception):
    pass


class ExcludeDecision:
    PRUNE = "PRUNE"
    BLOCK_REVIEW = "BLOCK_REVIEW"
    ALLOW = "ALLOW"


class ExcludeEngine:
    def __init__(self, manifest: dict, exclude_rules: dict):
        self.manifest = manifest
        self.exclude_rules = exclude_rules
        self.rules = exclude_rules.get("rules", [])
        self.dependency_exceptions = {
            item["path"]: item
            for item in exclude_rules.get("approved_dependency_exceptions", [])
        }
        self.content_scanner_cfg = exclude_rules.get("content_scanner", {})
        self.content_patterns = []
        for p in self.content_scanner_cfg.get("patterns", []):
            try:
                self.content_patterns.append(
                    {
                        "name": p["name"],
                        "regex": re.compile(p["pattern"]),
                        "severity": p.get("severity", "BLOCK"),
                    }
                )
            except re.error:
                pass
        self.copyright_exceptions = self.content_scanner_cfg.get(
            "approved_copyright_exceptions", []
        )
        self.approved_symlink_prefixes = [
            p.lower() for p in manifest.get("approved_symlink_prefixes", [])
        ]
        self.audit_records = []
        self._verified_export_trees: Set[str] = set()
        self._verified_scan_oids: Set[Tuple[bool, str]] = set()
        self._effective_cache: Dict[Tuple[str, str, bool], Tuple[str, str, Optional[str]]] = {}

    def _expand_braces(self, pattern: str) -> List[str]:
        # Expands patterns like *.{docx,xlsx} or {*.pem,*.key}
        m = re.search(r"\{([^}]+)\}", pattern)
        if not m:
            return [pattern]
        prefix = pattern[: m.start()]
        suffix = pattern[m.end() :]
        options = m.group(1).split(",")
        res = []
        for opt in options:
            sub = prefix + opt.strip() + suffix
            res.extend(self._expand_braces(sub))
        return res

    def evaluate_single_node(
        self, path: str, mode: str = "100644"
    ) -> Tuple[str, str, Optional[str]]:
        """
        Node-level policy evaluation for a single path (directory prefix or leaf)
        using case-insensitive pattern/prefix matching and exact-match dependency exceptions.
        """
        # 1. Exact-match approved dependency exceptions (only for regular/executable blobs)
        if path in self.dependency_exceptions and mode in ALLOWED_SHARED_BLOB_MODES:
            item = self.dependency_exceptions[path]
            return (
                ExcludeDecision.ALLOW,
                "APPROVED_DEPENDENCY_EXCEPTION",
                item.get("reason", ""),
            )

        path_lower = path.lower()
        basename_lower = path_lower.split("/")[-1]

        # 2. Hard manifest check: explicit forbidden prefixes (case-insensitive)
        for prefix in self.manifest.get("explicit_forbidden_prefixes", []):
            prefix_lower = prefix.lower()
            prefix_clean = prefix_lower.rstrip("/")
            if path_lower.startswith(prefix_lower) or path_lower == prefix_clean:
                return (
                    ExcludeDecision.PRUNE,
                    "MANIFEST_EXPLICIT_FORBIDDEN",
                    f"Prefix forbidden: {prefix}",
                )

        # 3. App scope check (case-insensitive)
        app_scope = self.manifest.get("app_scope", {})
        allowed_apps = {a.lower() for a in app_scope.get("allowed_apps", [])}
        allowed_files = {f.lower() for f in app_scope.get("allowed_files", [])}
        if path_lower.startswith("app/"):
            parts_orig = path.split("/")
            parts_lower = path_lower.split("/")
            if len(parts_lower) >= 2:
                sub_lower = parts_lower[1]
                if (
                    len(parts_lower) == 2
                    and not mode.startswith("04")
                    and sub_lower in allowed_files
                ):
                    pass
                elif sub_lower in allowed_apps:
                    pass
                else:
                    return (
                        ExcludeDecision.PRUNE,
                        "APP_SCOPE_RESTRICTED",
                        f"Non-allowed app: {parts_orig[1]}",
                    )

        # 4. Exclude rules evaluation (case-insensitive)
        for rule in self.rules:
            action = rule.get("action", ExcludeDecision.PRUNE)
            category = rule.get("category", "")
            raw_pattern = rule.get("pattern", "")
            rule_id = rule.get("rule_id", "UNKNOWN_RULE")
            expanded = self._expand_braces(raw_pattern)

            for pat in expanded:
                pat_lower = pat.lower()
                matched = False
                if category == "PATH":
                    if "!(" in pat_lower:
                        if path_lower.startswith("app/"):
                            parts_lower = path_lower.split("/")
                            if len(parts_lower) >= 2 and parts_lower[1] not in (
                                "mickey_smart",
                                "makefile",
                            ):
                                matched = True
                    elif pat_lower.startswith("**/"):
                        sub_pat = pat_lower[3:]
                        if sub_pat.endswith("/**"):
                            dir_name = sub_pat[:-3]
                            if (
                                fnmatch.fnmatchcase(path_lower, pat_lower)
                                or fnmatch.fnmatchcase(path_lower, f"*{sub_pat}")
                                or path_lower == dir_name
                                or path_lower.startswith(f"{dir_name}/")
                                or path_lower.endswith(f"/{dir_name}")
                                or f"/{dir_name}/" in path_lower
                            ):
                                matched = True
                        else:
                            if (
                                fnmatch.fnmatchcase(path_lower, pat_lower)
                                or fnmatch.fnmatchcase(path_lower, f"*{sub_pat}")
                                or fnmatch.fnmatchcase(basename_lower, sub_pat)
                            ):
                                matched = True
                    elif pat_lower.endswith("/**"):
                        prefix = pat_lower[:-3]
                        if path_lower.startswith(f"{prefix}/") or path_lower == prefix:
                            matched = True
                    else:
                        if fnmatch.fnmatchcase(path_lower, pat_lower):
                            matched = True
                elif category == "FILENAME":
                    if fnmatch.fnmatchcase(basename_lower, pat_lower):
                        matched = True

                if matched:
                    return action, rule_id, rule.get("description", "")

        # 5. Manifest roots allowlist check (case-insensitive)
        allowed_roots = {r.lower() for r in self.manifest.get("allowed_roots", [])}
        root_files = {f.lower() for f in self.manifest.get("root_files_allowlist", [])}
        top_lower = path_lower.split("/")[0]
        top_orig = path.split("/")[0]
        if "/" not in path_lower:
            if (
                mode.startswith("04")
                or path_lower in allowed_roots
                or path_lower == "app"
            ):
                if path_lower in allowed_roots or path_lower == "app":
                    return ExcludeDecision.ALLOW, "ROOT_DIR_ALLOWLISTED", ""
                else:
                    return (
                        ExcludeDecision.PRUNE,
                        "ROOT_DIR_NOT_ALLOWLISTED",
                        f"Root directory not in allowlist: {path}",
                    )
            else:
                if path_lower not in root_files:
                    return (
                        ExcludeDecision.PRUNE,
                        "ROOT_FILE_NOT_ALLOWLISTED",
                        f"Root file not in allowlist: {path}",
                    )
        else:
            if top_lower not in allowed_roots and top_lower != "app":
                return (
                    ExcludeDecision.PRUNE,
                    "ROOT_DIR_NOT_ALLOWLISTED",
                    f"Root directory not in allowlist: {top_orig}",
                )

        return (
            ExcludeDecision.ALLOW,
            "DEFAULT_ALLOW",
            "Passed manifest and exclude rules",
        )

    def evaluate_effective_path(
        self, path: str, mode: str = "100644", is_tree: bool = False
    ) -> Tuple[str, str, Optional[str]]:
        cache_key = (path, mode, is_tree, len(self.rules))
        if cache_key in self._effective_cache:
            return self._effective_cache[cache_key]
        res = self._evaluate_effective_path_uncached(path, mode=mode, is_tree=is_tree)
        self._effective_cache[cache_key] = res
        return res

    def _evaluate_effective_path_uncached(
        self, path: str, mode: str = "100644", is_tree: bool = False
    ) -> Tuple[str, str, Optional[str]]:
        """
        Unified Contract 1 decision function (Section 2.2):
        - Exact-match approved_dependency_exceptions with mode in ('100644', '100755') -> ALLOW
        - Ancestor-accumulated evaluation from root to leaf:
          any BLOCK_REVIEW -> BLOCK_REVIEW; else any PRUNE -> PRUNE
        - Platform path validation:
          if invalid, PRUNE if in PRUNE domain else BLOCK_REVIEW (INVALID_PLATFORM_PATH)
        - Mode matrix check:
          if mode not in ('100644', '100755', '040000'), PRUNE if mode == '120000' and in PRUNE domain
          else BLOCK_REVIEW (UNSUPPORTED_SHARED_GIT_MODE)
        """
        effective_mode = "040000" if (is_tree and mode == "100644") else mode

        platform_valid = True
        platform_err = ""
        try:
            validate_platform_rel_path(path)
        except PathValidationError as e:
            platform_valid = False
            platform_err = str(e)

        # 1. Exact-match approved dependency exceptions for valid blob modes
        if (
            platform_valid
            and path in self.dependency_exceptions
            and effective_mode in ALLOWED_SHARED_BLOB_MODES
        ):
            item = self.dependency_exceptions[path]
            return (
                ExcludeDecision.ALLOW,
                "APPROVED_DEPENDENCY_EXCEPTION",
                item.get("reason", ""),
            )

        # 2. Evaluate all ancestor directory prefixes and the leaf node
        ancestors = collect_ancestor_dirs(path) if path else []
        first_block: Optional[Tuple[str, str, Optional[str]]] = None
        first_prune: Optional[Tuple[str, str, Optional[str]]] = None

        for anc in ancestors:
            dec, rule_id, reason = self.evaluate_single_node(anc, mode="040000")
            if dec == ExcludeDecision.BLOCK_REVIEW and first_block is None:
                first_block = (dec, rule_id, f"Ancestor '{anc}' blocked: {reason}")
            elif dec == ExcludeDecision.PRUNE and first_prune is None:
                first_prune = (dec, rule_id, f"Ancestor '{anc}' pruned: {reason}")

        leaf_dec, leaf_rule_id, leaf_reason = self.evaluate_single_node(
            path, mode=effective_mode
        )
        if leaf_dec == ExcludeDecision.BLOCK_REVIEW and first_block is None:
            first_block = (leaf_dec, leaf_rule_id, leaf_reason)
        elif leaf_dec == ExcludeDecision.PRUNE and first_prune is None:
            first_prune = (leaf_dec, leaf_rule_id, leaf_reason)

        if first_block is not None:
            return first_block

        if first_prune is not None:
            if (
                effective_mode not in ALLOWED_SHARED_MODES
                and effective_mode != "120000"
            ):
                return (
                    ExcludeDecision.BLOCK_REVIEW,
                    "UNSUPPORTED_SHARED_GIT_MODE",
                    f"Unsupported git mode '{effective_mode}' at '{path}'",
                )
            return first_prune

        # 3. Path is in shared ALLOW domain; enforce platform validity and mode support matrix
        if not platform_valid:
            return (
                ExcludeDecision.BLOCK_REVIEW,
                "INVALID_PLATFORM_PATH",
                platform_err,
            )

        if effective_mode not in ALLOWED_SHARED_MODES:
            if effective_mode == "120000" and any(
                path.lower().startswith(pref) for pref in self.approved_symlink_prefixes
            ):
                return leaf_dec, leaf_rule_id, leaf_reason
            return (
                ExcludeDecision.BLOCK_REVIEW,
                "UNSUPPORTED_SHARED_GIT_MODE",
                f"Unsupported git mode '{effective_mode}' for shared path '{path}'",
            )

        return leaf_dec, leaf_rule_id, leaf_reason

    def evaluate_path(
        self, path: str, mode: str = "100644"
    ) -> Tuple[str, str, Optional[str]]:
        """
        Unified entry point delegating to evaluate_effective_path so all callers
        share ancestor-accumulated semantics, platform path validation, and mode checks.
        """
        return self.evaluate_effective_path(
            path, mode=mode, is_tree=mode.startswith("04")
        )

    def is_path_in_content_scan_scope(self, path: str) -> bool:
        if not self.content_scanner_cfg.get("enabled", False):
            return False
        path_lower = path.lower()
        for pat in self.content_scanner_cfg.get("scan_scope", []):
            pat_lower = pat.lower()
            if pat_lower.endswith("/**"):
                prefix = pat_lower[:-3]
                if path_lower.startswith(f"{prefix}/") or path_lower == prefix:
                    return True
            elif fnmatch.fnmatchcase(path_lower, pat_lower):
                return True
        return False

    def is_copyright_exempt(self, path: str) -> bool:
        path_lower = path.lower()
        for pat in self.copyright_exceptions:
            pat_lower = pat.lower()
            if pat_lower.endswith("/**"):
                prefix = pat_lower[:-3]
                if path_lower.startswith(f"{prefix}/") or path_lower == prefix:
                    return True
            elif fnmatch.fnmatchcase(path_lower, pat_lower):
                return True
        return False

    def scan_content_blob(
        self, path: str, blob_bytes: bytes
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        # Returns: (passed, violated_rule_name, redacted_hint)
        if not self.content_scanner_cfg.get("enabled", False):
            return True, None, None

        if not self.is_path_in_content_scan_scope(path):
            return True, None, None

        # Check copyright exemption
        if self.is_copyright_exempt(path):
            return True, None, "Copyright exemption applied"

        # Try decoding as UTF-8
        try:
            text = blob_bytes.decode("utf-8")
        except UnicodeDecodeError:
            # Binary or non-utf8 file in scanned scope
            return True, None, None

        # Check patterns
        for p in self.content_patterns:
            name = p["name"]
            regex = p["regex"]
            m = regex.search(text)
            if m:
                # Calculate line number
                line_no = text[: m.start()].count("\n") + 1
                redacted_hint = f"Matched {name} at line {line_no} (value redacted)"
                return False, name, redacted_hint

        return True, None, None

    def compute_shared_norm(
        self,
        git_adapter,
        tree_oid: str,
        normalizer: Optional[ContentNormalizer] = None,
        decrypt_fn: Optional[Callable[[bytes], bytes]] = None,
    ) -> Dict[str, Tuple[str, str]]:
        """
        Computes SharedNorm(T) -> {path: (mode, canon_hash)} for all ALLOW blobs in tree_oid.
        """
        norm = normalizer if normalizer is not None else ContentNormalizer()
        ls_fn = getattr(git_adapter, "ls_tree_r_z_strict", git_adapter.ls_tree_r_z)
        entries = ls_fn(tree_oid)
        shared_norm: Dict[str, Tuple[str, str]] = {}

        allowed_entries = []
        for entry in entries:
            path = entry["path"]
            mode = entry["mode"]
            oid = entry["oid"]
            entry_type = entry.get("type", "blob")
            is_tree = (entry_type == "tree") or mode.startswith("04")

            decision, _, _ = self.evaluate_effective_path(
                path, mode=mode, is_tree=is_tree
            )
            if decision != ExcludeDecision.ALLOW or is_tree:
                continue
            allowed_entries.append((path, mode, oid))

        batch_fn = getattr(git_adapter, "cat_file_blobs_batch", None)
        blob_map = (
            batch_fn([oid for _, _, oid in allowed_entries])
            if callable(batch_fn)
            else {}
        )

        for path, mode, oid in allowed_entries:
            raw_bytes = (
                blob_map[oid]
                if oid in blob_map
                else git_adapter.cat_file_blob(oid)
            )
            plain_bytes = decrypt_fn(raw_bytes) if decrypt_fn is not None else raw_bytes
            chash = norm.canon_hash(path, plain_bytes)
            shared_norm[path] = (mode, chash)

        return shared_norm

    def verify_shared_norm_pair(
        self,
        git_a,
        tree_a: str,
        git_b,
        tree_b: str,
        normalizer: Optional[ContentNormalizer] = None,
        decrypt_fn: Optional[Callable[[bytes], bytes]] = None,
    ) -> Tuple[bool, str]:
        """
        Fast SharedNorm equivalence check between tree_a and tree_b:
        When a shared path has the exact same mode and Git Blob OID in both trees,
        its canonical content is guaranteed identical without reading gigabytes of blobs.
        Only blobs whose OIDs differ between tree_a and tree_b are read and compared via CanonHash.
        """
        norm = normalizer if normalizer is not None else ContentNormalizer()
        ls_a = getattr(git_a, "ls_tree_r_z_strict", git_a.ls_tree_r_z)
        ls_b = getattr(git_b, "ls_tree_r_z_strict", git_b.ls_tree_r_z)

        allow_a: Dict[str, Tuple[str, str]] = {}
        for entry in ls_a(tree_a):
            path, mode, oid = entry["path"], entry["mode"], entry["oid"]
            is_tree = (entry.get("type", "blob") == "tree") or mode.startswith("04")
            dec, _, _ = self.evaluate_effective_path(path, mode=mode, is_tree=is_tree)
            if dec == ExcludeDecision.ALLOW and not is_tree:
                allow_a[path] = (mode, oid)

        allow_b: Dict[str, Tuple[str, str]] = {}
        for entry in ls_b(tree_b):
            path, mode, oid = entry["path"], entry["mode"], entry["oid"]
            is_tree = (entry.get("type", "blob") == "tree") or mode.startswith("04")
            dec, _, _ = self.evaluate_effective_path(path, mode=mode, is_tree=is_tree)
            if dec == ExcludeDecision.ALLOW and not is_tree:
                allow_b[path] = (mode, oid)

        if set(allow_a.keys()) != set(allow_b.keys()):
            only_a = sorted(set(allow_a.keys()) - set(allow_b.keys()))[:5]
            only_b = sorted(set(allow_b.keys()) - set(allow_a.keys()))[:5]
            return False, f"Shared path set mismatch (only_a={only_a}, only_b={only_b})"

        diff_paths = []
        for path, (mode_a, oid_a) in allow_a.items():
            mode_b, oid_b = allow_b[path]
            if mode_a != mode_b:
                return False, f"Mode mismatch at '{path}': {mode_a} vs {mode_b}"
            if oid_a != oid_b or decrypt_fn is not None:
                if oid_a != oid_b:
                    diff_paths.append((path, oid_a, oid_b))

        if not diff_paths and decrypt_fn is None:
            return True, "SHARED_NORM_EQUAL"

        if not diff_paths and decrypt_fn is not None:
            return True, "SHARED_NORM_EQUAL"

        batch_a = getattr(git_a, "cat_file_blobs_batch", None)
        batch_b = getattr(git_b, "cat_file_blobs_batch", None)
        blobs_a = batch_a([oid_a for _, oid_a, _ in diff_paths]) if callable(batch_a) else {}
        blobs_b = batch_b([oid_b for _, _, oid_b in diff_paths]) if callable(batch_b) else {}

        for path, oid_a, oid_b in diff_paths:
            raw_a = blobs_a[oid_a] if oid_a in blobs_a else git_a.cat_file_blob(oid_a)
            raw_b = blobs_b[oid_b] if oid_b in blobs_b else git_b.cat_file_blob(oid_b)
            plain_b = decrypt_fn(raw_b) if decrypt_fn is not None else raw_b
            if norm.canon_hash(path, raw_a) != norm.canon_hash(path, plain_b):
                return False, f"CanonHash mismatch at '{path}'"

        return True, "SHARED_NORM_EQUAL"

    def validate_export_tree(
        self,
        git_adapter,
        tree_oid: str,
        decrypt_fn: Optional[Callable[[bytes], bytes]] = None,
    ) -> Tuple[bool, str]:
        """
        Implements ValidateExportTree(T_B) from Section 2.4:
        Verifies every entry in tree_oid:
        1) passes validate_platform_rel_path and fits CaseFoldedNamespaceTrie without collision
        2) has evaluate_effective_path == ALLOW (no PRUNE or BLOCK_REVIEW leaks)
        3) passes scan_content_blob for all entries in content scan scope
        Returns: (passed, details)
        """
        trie = CaseFoldedNamespaceTrie()
        ls_fn = getattr(git_adapter, "ls_tree_r_z_strict", git_adapter.ls_tree_r_z)
        entries = ls_fn(tree_oid)

        scan_candidates = []
        for entry in entries:
            path = entry["path"]
            mode = entry["mode"]
            oid = entry["oid"]
            entry_type = entry.get("type", "blob")
            is_tree = (entry_type == "tree") or mode.startswith("04")

            try:
                validate_platform_rel_path(path)
            except PathValidationError as e:
                return (
                    False,
                    f"Invalid platform path '{path}' in export tree {tree_oid}: {e}",
                )

            if not is_tree:
                try:
                    trie.insert_path(path, origin_tag="EXPORT")
                except NamespaceCollisionError as e:
                    return (
                        False,
                        f"Namespace collision in export tree {tree_oid} at '{path}': {e}",
                    )

            decision, rule_id, reason = self.evaluate_effective_path(
                path, mode=mode, is_tree=is_tree
            )
            if decision != ExcludeDecision.ALLOW:
                return (
                    False,
                    f"Export tree {tree_oid} contains non-exportable path '{path}' "
                    f"(decision={decision}, rule={rule_id}): {reason}",
                )

            if not is_tree and self.is_path_in_content_scan_scope(path):
                exempt = self.is_copyright_exempt(path)
                if (exempt, oid) not in self._verified_scan_oids:
                    scan_candidates.append((path, oid, exempt))

        batch_fn = getattr(git_adapter, "cat_file_blobs_batch", None)
        scan_blobs = (
            batch_fn([oid for _, oid, _ in scan_candidates])
            if callable(batch_fn) and scan_candidates
            else {}
        )
        for path, oid, exempt in scan_candidates:
            raw_bytes = (
                scan_blobs[oid]
                if oid in scan_blobs
                else git_adapter.cat_file_blob(oid)
            )
            plain_bytes = (
                decrypt_fn(raw_bytes) if decrypt_fn is not None else raw_bytes
            )
            passed, rule_name, hint = self.scan_content_blob(path, plain_bytes)
            if not passed:
                return (
                    False,
                    f"Export tree {tree_oid} failed content scan at '{path}' "
                    f"(rule={rule_name}): {hint}",
                )
            self._verified_scan_oids.add((exempt, oid))

        return True, "EXPORT_TREE_VALID"

    def record_audit(
        self, commit_oid: str, path: str, decision: str, rule_id: str, details: str
    ):
        self.audit_records.append(
            {
                "commit_oid": commit_oid,
                "path": path,
                "decision": decision,
                "rule_id": rule_id,
                "details": details,
            }
        )
