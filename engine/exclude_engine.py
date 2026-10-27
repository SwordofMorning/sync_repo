import re
import fnmatch
from typing import Dict, List, Tuple, Optional

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
            item["path"]: item for item in exclude_rules.get("approved_dependency_exceptions", [])
        }
        self.content_scanner_cfg = exclude_rules.get("content_scanner", {})
        self.content_patterns = []
        for p in self.content_scanner_cfg.get("patterns", []):
            try:
                self.content_patterns.append({
                    "name": p["name"],
                    "regex": re.compile(p["pattern"]),
                    "severity": p.get("severity", "BLOCK")
                })
            except re.error as e:
                pass
        self.copyright_exceptions = self.content_scanner_cfg.get("approved_copyright_exceptions", [])
        self.audit_records = []

    def _expand_braces(self, pattern: str) -> List[str]:
        # Expands patterns like *.{docx,xlsx} or {*.pem,*.key}
        m = re.search(r"\{([^}]+)\}", pattern)
        if not m:
            return [pattern]
        prefix = pattern[:m.start()]
        suffix = pattern[m.end():]
        options = m.group(1).split(",")
        res = []
        for opt in options:
            sub = prefix + opt.strip() + suffix
            res.extend(self._expand_braces(sub))
        return res

    def evaluate_path(self, path: str, mode: str = "100644") -> Tuple[str, str, Optional[str]]:
        # Returns: (Decision, rule_id, reason)
        # 1. Check approved dependency exceptions first
        if path in self.dependency_exceptions:
            item = self.dependency_exceptions[path]
            return ExcludeDecision.ALLOW, "APPROVED_DEPENDENCY_EXCEPTION", item.get("reason", "")

        # 2. Hard manifest check: explicit forbidden prefixes
        for prefix in self.manifest.get("explicit_forbidden_prefixes", []):
            if path.startswith(prefix):
                return ExcludeDecision.PRUNE, "MANIFEST_EXPLICIT_FORBIDDEN", f"Prefix forbidden: {prefix}"

        # 3. App scope check
        app_scope = self.manifest.get("app_scope", {})
        allowed_apps = set(app_scope.get("allowed_apps", []))
        allowed_files = set(app_scope.get("allowed_files", []))
        if path.startswith("app/"):
            parts = path.split("/")
            if len(parts) >= 2:
                sub = parts[1]
                if len(parts) == 2 and sub in allowed_files:
                    pass
                elif sub in allowed_apps:
                    pass
                else:
                    return ExcludeDecision.PRUNE, "APP_SCOPE_RESTRICTED", f"Non-allowed app: {sub}"

        # 4. Exclude rules evaluation
        basename = path.split("/")[-1]
        for rule in self.rules:
            action = rule.get("action", ExcludeDecision.PRUNE)
            category = rule.get("category", "")
            raw_pattern = rule.get("pattern", "")
            rule_id = rule.get("rule_id", "UNKNOWN_RULE")
            expanded = self._expand_braces(raw_pattern)

            for pat in expanded:
                matched = False
                if category == "PATH":
                    # Handle app/!(mickey_smart|Makefile)/** style
                    if "!(" in pat:
                        if path.startswith("app/"):
                            parts = path.split("/")
                            if len(parts) >= 2 and parts[1] not in ("mickey_smart", "Makefile"):
                                matched = True
                    elif pat.startswith("**/"):
                        sub_pat = pat[3:]
                        if fnmatch.fnmatchcase(path, pat) or fnmatch.fnmatchcase(path, f"*{sub_pat}"):
                            matched = True
                    elif pat.endswith("/**"):
                        prefix = pat[:-3]
                        if path.startswith(f"{prefix}/") or path == prefix:
                            matched = True
                    else:
                        if fnmatch.fnmatchcase(path, pat):
                            matched = True
                elif category == "FILENAME":
                    if fnmatch.fnmatchcase(basename, pat):
                        matched = True

                if matched:
                    return action, rule_id, rule.get("description", "")

        # 5. Manifest roots allowlist check
        allowed_roots = set(self.manifest.get("allowed_roots", []))
        root_files = set(self.manifest.get("root_files_allowlist", []))
        top = path.split("/")[0]
        if "/" not in path:
            if mode.startswith("04") or path in allowed_roots or path == "app":
                if path in allowed_roots or path == "app":
                    return ExcludeDecision.ALLOW, "ROOT_DIR_ALLOWLISTED", ""
                else:
                    return ExcludeDecision.PRUNE, "ROOT_DIR_NOT_ALLOWLISTED", f"Root directory not in allowlist: {path}"
            else:
                if path not in root_files:
                    return ExcludeDecision.PRUNE, "ROOT_FILE_NOT_ALLOWLISTED", f"Root file not in allowlist: {path}"
        else:
            if top not in allowed_roots and top != "app":
                return ExcludeDecision.PRUNE, "ROOT_DIR_NOT_ALLOWLISTED", f"Root directory not in allowlist: {top}"

        return ExcludeDecision.ALLOW, "DEFAULT_ALLOW", "Passed manifest and exclude rules"

    def is_path_in_content_scan_scope(self, path: str) -> bool:
        if not self.content_scanner_cfg.get("enabled", False):
            return False
        for pat in self.content_scanner_cfg.get("scan_scope", []):
            if pat.endswith("/**"):
                prefix = pat[:-3]
                if path.startswith(f"{prefix}/") or path == prefix:
                    return True
            elif fnmatch.fnmatchcase(path, pat):
                return True
        return False

    def is_copyright_exempt(self, path: str) -> bool:
        for pat in self.copyright_exceptions:
            if pat.endswith("/**"):
                prefix = pat[:-3]
                if path.startswith(f"{prefix}/") or path == prefix:
                    return True
            elif fnmatch.fnmatchcase(path, pat):
                return True
        return False

    def scan_content_blob(self, path: str, blob_bytes: bytes) -> Tuple[bool, Optional[str], Optional[str]]:
        # Returns: (passed, violated_rule_name, redacted_hint)
        if not self.content_scanner_cfg.get("enabled", False):
            return True, None, None

        # Check if in scan scope
        in_scope = False
        for pat in self.content_scanner_cfg.get("scan_scope", []):
            if pat.endswith("/**"):
                prefix = pat[:-3]
                if path.startswith(f"{prefix}/") or path == prefix:
                    in_scope = True
                    break
            elif fnmatch.fnmatchcase(path, pat):
                in_scope = True
                break

        if not in_scope:
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
                line_no = text[:m.start()].count("\n") + 1
                redacted_hint = f"Matched {name} at line {line_no} (value redacted)"
                return False, name, redacted_hint

        return True, None, None

    def record_audit(self, commit_oid: str, path: str, decision: str, rule_id: str, details: str):
        self.audit_records.append({
            "commit_oid": commit_oid,
            "path": path,
            "decision": decision,
            "rule_id": rule_id,
            "details": details
        })
