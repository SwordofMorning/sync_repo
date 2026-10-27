"""Logical integrity and fail-closed, whole-delta physical DLP attestation."""

import base64
import hashlib
import os
import secrets
from typing import Callable, List, Optional, Tuple

from engine.content_normalizer import ContentNormalizer, normalize_lf_idempotent
from engine.git_adapter import GitAdapter
from engine.path_validator import (
    ALLOWED_SHARED_BLOB_MODES,
    validate_platform_rel_path,
    verify_no_worktree_reparse_points,
)
from engine.workspace_materializer import (
    CorruptedCipherBlobError,
    TSD_MAGIC_HEADER,
    WorkspaceMaterializer,
    _blob_oid,
    _write_fsynced,
)

DLP_CONTRACT_SPEC_VERSION = "3.0"
DEFAULT_ENCRYPTION_EXTENSIONS = (
    ".c", ".h", ".cpp", ".hpp", ".py", ".json", ".txt", ".sh", ".mk", ".xml"
)


class GateStatus:
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"


class _LogicalFailure(Exception):
    pass


class DlpVerifier:
    def __init__(
        self, target_git: GitAdapter, target_worktree: str,
        physical_reader: Optional[Callable[[str], bytes]] = None,
    ):
        self.target_git = target_git
        self.target_worktree = os.path.abspath(target_worktree)
        self.physical_reader = physical_reader
        self.normalizer = ContentNormalizer()
        self.last_canary_report: Optional[dict] = None

    @staticmethod
    def _path(root: str, rel_path: str) -> str:
        validate_platform_rel_path(rel_path)
        if any(part.casefold() == ".git" for part in rel_path.split("/")):
            raise _LogicalFailure("Git metadata is not a physical audit target")
        verify_no_worktree_reparse_points(root, rel_path)
        return os.path.join(root, *rel_path.split("/"))

    @staticmethod
    def _read(path: str) -> bytes:
        with open(path, "rb") as stream:
            return stream.read()

    def _physical(self, path: str, root: Optional[str] = None) -> bytes:
        if self.physical_reader is not None:
            observed = self.physical_reader(path)
        elif os.name == "nt":
            # Never mistake the authorized Python/DLP logical view for at-rest
            # bytes. Only an out-of-tree worker may supply physical observations.
            root = root or self.target_worktree
            worker = WorkspaceMaterializer(self.target_git, root,
                                           tx_id="probe_" + secrets.token_hex(12))
            manifest = {"tx_id": worker.tx_id, "nonce": secrets.token_hex(16), "items": [
                {"mode": "PROBE_PHYSICAL_HEADER", "target_abs_path": path, "include_bytes": True}
            ]}
            try:
                result = worker._execute_manifest(manifest)
                item = result["items"][0]
                observed = base64.b64decode(item["physical_bytes_base64"], validate=True)
                if (item["physical_size"] != len(observed)
                        or item["physical_sha256"] != hashlib.sha256(observed).hexdigest()
                        or item["physical_header_hex"] != observed[:16].hex()
                        or item["has_tsd_header"] != observed.startswith(TSD_MAGIC_HEADER)):
                    raise ValueError("Physical observer returned inconsistent attestation")
            finally:
                # Only this probe's own private staging is cleaned up.
                if os.path.isdir(worker.staging_dir):
                    import shutil
                    shutil.rmtree(worker.staging_dir)
        else:
            observed = self._read(path)
        if not isinstance(observed, bytes):
            raise TypeError("Physical reader must return physical bytes")
        return observed

    def _logical_bytes(self, rel_path: str, oid: str, mode: str) -> bytes:
        if mode not in ALLOWED_SHARED_BLOB_MODES:
            raise _LogicalFailure(f"Unsupported tracked mode {mode}: {rel_path}")
        target = self._path(self.target_worktree, rel_path)
        if not os.path.isfile(target):
            raise _LogicalFailure(f"File missing in workspace: {rel_path}")
        expected = self.target_git.cat_file_blob(oid)
        data = self._read(target)
        if _blob_oid(expected, len(oid)) != oid:
            raise _LogicalFailure(f"Git blob OID mismatch: {rel_path}")
        if data != expected:
            # CRLF equivalence is ONLY permitted for text. Binary files must not
            # acquire the old verifier's lossy CRLF fallback.
            kind = self.normalizer.classify_blob_kind(rel_path, expected)
            if (kind == "BINARY" or self.normalizer.classify_blob_kind(rel_path, data) == "BINARY"
                    or normalize_lf_idempotent(data) != normalize_lf_idempotent(expected)):
                raise _LogicalFailure(f"Logical hash mismatch for {rel_path}: expected {oid}")
        return expected

    def verify_logical_integrity(self, tree_oid: str, sample_limit: int = 500) -> Tuple[bool, str]:
        """Compatibility API; sample_limit is retained but NEVER limits coverage."""
        checked = 0
        try:
            for entry in self.target_git.ls_tree_r_z_strict(tree_oid):
                self._logical_bytes(entry["path"], entry["oid"], entry["mode"])
                checked += 1
        except Exception as exc:
            return False, str(exc)
        return True, f"Verified {checked} files logically matching Git Blob OIDs (100% coverage)"

    def verify_physical_dlp_headers(self, sample_limit: int = 50) -> Tuple[bool, str]:
        """Compatibility API backed by a 100% tracked-file baseline, not a sample."""
        try:
            tree = self.target_git.rev_parse("HEAD^{tree}")
            status, reason, report = self.verify_full_worktree_physical_baseline(tree, "B")
        except Exception as exc:
            return False, f"UNKNOWN: {exc}"
        return status == GateStatus.PASS, f"{status}: {reason}; checked={report['checked']}"

    @staticmethod
    def _encrypted_path(path: str, extensions: Optional[List[str]]) -> bool:
        extensions = DEFAULT_ENCRYPTION_EXTENSIONS if extensions is None else extensions
        return any(path.lower().endswith(ext.lower() if ext.startswith(".") else "." + ext.lower())
                   for ext in extensions)

    def _audit_written(
        self, path: str, oid: str, mode: str, role: str,
        extensions: Optional[List[str]],
    ) -> dict:
        expected = self._logical_bytes(path, oid, mode)
        target = self._path(self.target_worktree, path)
        physical = self._physical(target)
        has_header = physical.startswith(TSD_MAGIC_HEADER)
        digest = hashlib.sha256(physical).hexdigest()
        if role == "A":
            if has_header or len(physical) != len(expected) or digest != hashlib.sha256(expected).hexdigest():
                raise _LogicalFailure(f"Repo A physical plaintext/hash mismatch: {path}")
        elif expected and self._encrypted_path(path, extensions):
            if not has_header or len(physical) < 8192 or len(physical) % 4096:
                raise _LogicalFailure(f"Repo B missing/invalid physical TSD encryption: {path}")
        return {"path": path, "status": GateStatus.PASS, "physical_size": len(physical),
                "physical_sha256": digest, "has_tsd_header": has_header}

    def verify_transaction_delta_gates(
        self, direction: str, old_tree_oid: str, new_tree_oid: str,
        encryption_extensions: Optional[List[str]] = None, observer_healthy: bool = True,
    ) -> Tuple[str, str, dict]:
        report = {"direction": direction, "checked": 0, "written": 0, "deleted": 0, "items": []}
        if direction not in ("A2B", "B2A"):
            return GateStatus.FAIL, "INVALID_DIRECTION", report
        if not observer_healthy:
            return GateStatus.UNKNOWN, "PHYSICAL_OBSERVER_UNHEALTHY", report
        try:
            for entry in self.target_git.diff_tree_raw(old_tree_oid, new_tree_oid):
                path, status = entry["path"], entry["status"]
                target = self._path(self.target_worktree, path)
                if status == "D":
                    if os.path.lexists(target):
                        raise _LogicalFailure(f"Deleted path still physically exists: {path}")
                    report["deleted"] += 1
                    report["items"].append({"path": path, "status": GateStatus.PASS, "exists": False})
                elif status in ("A", "M", "T"):
                    report["items"].append(self._audit_written(
                        path, entry["new_oid"], entry["new_mode"],
                        "A" if direction == "B2A" else "B", encryption_extensions,
                    ))
                    report["written"] += 1
                else:
                    raise _LogicalFailure(f"Unsupported delta operation: {status}")
                report["checked"] += 1
        except _LogicalFailure as exc:
            report["error"] = str(exc)
            return GateStatus.FAIL, str(exc), report
        except Exception as exc:
            report["error"] = str(exc)
            return GateStatus.UNKNOWN, f"AUDIT_UNAVAILABLE: {exc}", report
        reason = "DELTA_GATES_PASS" if report["written"] else "VACUOUS_PASS_NO_WRITTEN_FILES"
        return GateStatus.PASS, reason, report

    def verify_full_worktree_physical_baseline(
        self, tree_oid: str, role: str, encryption_extensions: Optional[List[str]] = None,
        observer_healthy: bool = True,
    ) -> Tuple[str, str, dict]:
        report = {"tree_oid": tree_oid, "role": role, "checked": 0, "items": []}
        role = role.upper().replace("REPO_", "").replace("REPO ", "")
        if role not in ("A", "B"):
            return GateStatus.FAIL, "INVALID_REPOSITORY_ROLE", report
        if not observer_healthy:
            return GateStatus.UNKNOWN, "PHYSICAL_OBSERVER_UNHEALTHY", report
        try:
            for entry in self.target_git.ls_tree_r_z_strict(tree_oid):
                report["items"].append(self._audit_written(
                    entry["path"], entry["oid"], entry["mode"], role, encryption_extensions
                ))
                report["checked"] += 1
        except _LogicalFailure as exc:
            report["error"] = str(exc)
            return GateStatus.FAIL, str(exc), report
        except Exception as exc:
            report["error"] = str(exc)
            return GateStatus.UNKNOWN, f"AUDIT_UNAVAILABLE: {exc}", report
        return GateStatus.PASS, "FULL_BASELINE_PHYSICAL_AUDIT_PASS", report

    def run_preflight_canary_probes(
        self, worktree_a: str, worktree_b: str, materializer_a: WorkspaceMaterializer,
        encrypt_write_hook: Optional[Callable[[bytes], bytes]] = None,
    ) -> Tuple[str, str, dict]:
        """Exercise the SAME .old bridge and actual target replacement as production.

        Hooks model the driver/observer in unit tests. They are not an encryption
        implementation and cannot certify a real Windows DLP deployment.
        """
        nonce = secrets.token_hex(16)
        plain = secrets.token_hex(32).encode("ascii")  # known 64-byte vector
        expected_sha256 = hashlib.sha256(plain).hexdigest()
        worktree_a, worktree_b = os.path.abspath(worktree_a), os.path.abspath(worktree_b)
        report = {"nonce": nonce, "expected_size": len(plain),
                  "expected_sha256": expected_sha256,
                  "observer": {"contract_spec_version": DLP_CONTRACT_SPEC_VERSION,
                               "parent_pid": os.getpid(),
                               "reader": "injected" if self.physical_reader else
                                         ("out_of_tree_worker" if os.name == "nt" else "posix_physical")},
                  "probes": {}, "cleanup_errors": []}
        canary_b = self._path(worktree_b, f".sync_canary_{nonce}.c")
        target_a = self._path(worktree_a, f".sync_canary_target_{nonce}.c")
        stage = None
        current = "P1"
        try:
            if worktree_a != materializer_a.target_worktree:
                raise _LogicalFailure("P4 materializer is not bound to the actual Repo A worktree")
            materializer_a._safe_write_bytes(canary_b, plain, is_symlink=False)
            if encrypt_write_hook:
                cipher_fixture = encrypt_write_hook(plain)
                if not isinstance(cipher_fixture, bytes):
                    raise _LogicalFailure("Encryption fixture must return bytes")
                _write_fsynced(canary_b, cipher_fixture)
            cipher = self._physical(canary_b, root=worktree_b)
            if cipher == plain:
                report["probes"]["P1"] = {"status": GateStatus.UNKNOWN,
                                                  "reason": "OBSERVER_TRANSPARENT_DECRYPTION"}
                return self._canary_result(GateStatus.UNKNOWN, "OBSERVER_TRANSPARENT_DECRYPTION", report)
            if (not cipher.startswith(TSD_MAGIC_HEADER) or len(cipher) < 8192
                    or len(cipher) % 4096):
                raise _LogicalFailure("P1 missing/invalid physical TSD encryption")
            report["probes"]["P1"] = {"status": GateStatus.PASS, "physical_size": len(cipher),
                                              "physical_sha256": hashlib.sha256(cipher).hexdigest()}
            current = "P2"
            output = materializer_a.decrypt_blob_via_old_channel(
                cipher, expected_source_oid=_blob_oid(cipher), hint_path="canary-memory-blob"
            )
            if len(output) != len(plain) or hashlib.sha256(output).hexdigest() != expected_sha256:
                raise _LogicalFailure("P2 decrypted bytes do not match the independently known vector")
            report["probes"]["P2"] = {"status": GateStatus.PASS, "plaintext_sha256": expected_sha256}
            current = "P3"
            negatives = [TSD_MAGIC_HEADER + b"\0" * 64, cipher[:-1], cipher[:4096]]
            rejected = 0
            for corrupt in negatives:
                try:
                    materializer_a.decrypt_blob_via_old_channel(corrupt, hint_path="canary-corrupt")
                except CorruptedCipherBlobError:
                    rejected += 1
                else:
                    raise _LogicalFailure("P3 corrupt/truncated cipher was accepted")
            report["probes"]["P3"] = {"status": GateStatus.PASS, "rejected_vectors": rejected}
            current = "P4"
            materializer_a._ensure_staging_dir()
            _write_fsynced(target_a, b"existing-canary-target\n")
            stage = os.path.join(materializer_a.staging_dir, f"canary_out_{nonce}.old")
            _write_fsynced(stage, plain)
            manifest = {"tx_id": materializer_a.tx_id, "nonce": nonce, "direction": "B2A",
                        "target_worktree": worktree_a, "items": [
                            {"mode": "REPLACE_UNENCRYPTED", "stage_old_path": stage,
                             "target_abs_path": target_a, "expected_size": len(plain),
                             "expected_sha256": expected_sha256}
                        ]}
            result = materializer_a._execute_manifest(manifest)
            materializer_a._assert_result(manifest, result)
            physical_a = self._physical(target_a, root=worktree_a)
            if (physical_a.startswith(TSD_MAGIC_HEADER) or len(physical_a) != len(plain)
                    or hashlib.sha256(physical_a).hexdigest() != expected_sha256):
                raise _LogicalFailure("P4 real target worktree replacement is not physical plaintext")
            report["probes"]["P4"] = {"status": GateStatus.PASS, "target_abs_path": target_a,
                                              "stage_old_path": stage,
                                              "physical_sha256": expected_sha256}
            return self._canary_result(GateStatus.PASS, "CANARY_P1_P2_P3_P4_PASS", report)
        except (CorruptedCipherBlobError, _LogicalFailure) as exc:
            report["probes"][current] = {"status": GateStatus.FAIL, "error": str(exc)}
            return self._canary_result(GateStatus.FAIL, str(exc), report)
        except Exception as exc:
            report["probes"][current] = {"status": GateStatus.UNKNOWN, "error": str(exc)}
            return self._canary_result(GateStatus.UNKNOWN, f"CANARY_UNAVAILABLE: {exc}", report)
        finally:
            for path in (canary_b, target_a, stage):
                if path and os.path.lexists(path):
                    try:
                        os.remove(path)
                    except OSError as exc:
                        report["cleanup_errors"].append(str(exc))

    def _canary_result(self, status: str, reason: str, report: dict) -> Tuple[str, str, dict]:
        report.update(status=status, reason=reason)
        self.last_canary_report = report
        return status, reason, report
