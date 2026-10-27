"""Durable worktree staging and physical-state-preserving DLP materialization."""

import base64
import ctypes
import hashlib
import json
import os
import secrets
import subprocess
import time
from typing import Callable, Dict, List, Optional

from engine.git_adapter import GitAdapter
from engine.path_validator import (
    ALLOWED_SHARED_BLOB_MODES,
    PathValidationError,
    validate_platform_rel_path,
    verify_no_worktree_reparse_points,
)

TSD_MAGIC_HEADER = b"%TSD-Header-###%"
_IS_WINDOWS = os.name == "nt"


class MaterializeError(Exception):
    pass


class CorruptedCipherBlobError(MaterializeError):
    pass


def _blob_oid(data: bytes, oid_length: int = 40) -> str:
    digest = hashlib.sha256 if oid_length == 64 else hashlib.sha1
    return digest(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def _write_fsynced(path: str, data: bytes) -> None:
    with open(path, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _fsync_dir(path: str) -> None:
    if not _IS_WINDOWS:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _write_json_atomic(path: str, value: dict) -> None:
    _write_fsynced(path + ".tmp", json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8"))
    os.replace(path + ".tmp", path)
    _fsync_dir(os.path.dirname(path))


class _FILETIME(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


def _windows_kernel32():
    from ctypes import wintypes

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetCurrentProcess.argtypes = []
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(_FILETIME)] * 4
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
    kernel.TerminateProcess.restype = wintypes.BOOL
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.WaitForSingleObject.restype = wintypes.DWORD
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.CloseHandle.restype = wintypes.BOOL
    return kernel


def _process_filetime(kernel, handle) -> int:
    created, exited, system, user = (_FILETIME() for _ in range(4))
    if not kernel.GetProcessTimes(handle, ctypes.byref(created), ctypes.byref(exited),
                                  ctypes.byref(system), ctypes.byref(user)):
        raise MaterializeError("GetProcessTimes failed; process identity is unverified")
    return (created.high << 32) | created.low


def get_current_proc_filetime() -> int:
    if not _IS_WINDOWS:
        return 0
    kernel = _windows_kernel32()
    return _process_filetime(kernel, kernel.GetCurrentProcess())


def terminate_lingering_worker(lease: dict) -> str:
    """Fence a Windows writer using ONE kernel handle, never a PID-based kill."""
    pid = lease.get("worker_pid")
    if not pid:
        return "not_registered"
    if not _IS_WINDOWS:
        # There are no asynchronous POSIX writers in this implementation. Do not
        # emulate handle-bound termination with a racy kill(pid).
        return "unsupported_platform"
    expected = lease.get("worker_create_time_ft")
    if not expected or int(pid) <= 0:
        raise MaterializeError("Cannot terminate a worker without its creation FILETIME")
    kernel = _windows_kernel32()
    handle = kernel.OpenProcess(0x1000 | 0x0001 | 0x00100000, False, int(pid))
    if not handle:
        error = ctypes.get_last_error()
        if error in (87, 1168):  # invalid PID / process no longer exists
            return "already_exited"
        raise MaterializeError(f"OpenProcess failed for worker {pid}: WinError {error}")
    try:
        if _process_filetime(kernel, handle) != int(expected):
            return "pid_reused_skipped"
        if kernel.WaitForSingleObject(handle, 0) == 0:
            return "already_exited"
        if not kernel.TerminateProcess(handle, 137):
            if kernel.WaitForSingleObject(handle, 0) != 0:
                raise MaterializeError("TerminateProcess failed; worker may still be active")
        if kernel.WaitForSingleObject(handle, 10000) != 0:
            raise MaterializeError("Worker termination was not confirmed by its kernel handle")
        return "terminated"
    finally:
        kernel.CloseHandle(handle)


class WorkspaceMaterializer:
    def __init__(
        self, target_git: GitAdapter, target_worktree: str, tx_id: str = "default",
        direction: str = "A2B", worker_script_path: Optional[str] = None,
        unmonitored_runner: Optional[Callable[[dict], dict]] = None,
        decrypt_read_hook: Optional[Callable[[str, bytes], bytes]] = None,
    ):
        validate_platform_rel_path(tx_id)
        if "/" in tx_id or tx_id.casefold() == ".git":
            raise MaterializeError("tx_id must be a single safe directory component")
        self.target_git = target_git
        self.target_worktree = os.path.abspath(target_worktree)
        self.tx_id = tx_id
        self.direction = self._direction(direction)
        self.worker_script_path = os.path.abspath(worker_script_path or os.path.join(
            os.path.dirname(__file__), "..", "scripts", "file_ops_worker.ps1"
        ))
        self.unmonitored_runner = unmonitored_runner
        self.decrypt_read_hook = decrypt_read_hook
        self.staging_dir = os.path.join(self.target_worktree, ".git", "sync_staging", tx_id)
        self.lock_backoff = [0.2, 0.5, 1.0, 2.0]
        self.worker_timeout = 120.0
        self.last_staging_info: Optional[dict] = None
        self.last_executor_lease: Optional[dict] = None

    @staticmethod
    def _direction(direction: str) -> str:
        value = direction.upper()
        if value not in ("A2B", "B2A"):
            raise MaterializeError(f"Unsupported materialization direction: {direction}")
        return value

    def _target_path(self, rel_path: str) -> str:
        try:
            validate_platform_rel_path(rel_path)
            if any(part.casefold() == ".git" for part in rel_path.split("/")):
                raise PathValidationError("Git metadata is never a worktree delta target")
            verify_no_worktree_reparse_points(self.target_worktree, rel_path)
        except PathValidationError as exc:
            raise MaterializeError(str(exc)) from exc
        return os.path.join(self.target_worktree, *rel_path.split("/"))

    def _ensure_staging_dir(self) -> None:
        verify_no_worktree_reparse_points(
            self.target_worktree, f".git/sync_staging/{self.tx_id}"
        )
        if not os.path.isdir(os.path.join(self.target_worktree, ".git")):
            raise MaterializeError("DLP staging requires a worktree with a .git directory")
        os.makedirs(self.staging_dir, exist_ok=True)
        _fsync_dir(os.path.dirname(self.staging_dir))

    def decrypt_blob_via_old_channel(
        self, raw_bytes: bytes, expected_source_oid: Optional[str] = None,
        hint_path: str = "blob",
    ) -> bytes:
        if not raw_bytes.startswith(TSD_MAGIC_HEADER):
            return raw_bytes
        if len(raw_bytes) < 8192 or len(raw_bytes) % 4096:
            raise CorruptedCipherBlobError(f"Invalid cipher block size for {hint_path}")
        if expected_source_oid and _blob_oid(raw_bytes, len(expected_source_oid)) != expected_source_oid:
            raise CorruptedCipherBlobError(f"Cipher blob OID mismatch for {hint_path}")
        self._ensure_staging_dir()
        ns = time.time_ns() if hasattr(time, "time_ns") else int(time.time() * 1_000_000_000)
        tmp_old_path = os.path.join(self.staging_dir, f"dec_{os.getpid()}_{ns}.old")
        created = False
        try:
            # Exclusive creation prevents reuse; never unlink somebody else's
            # file if a timestamp collision or hostile pre-existing path exists.
            with open(tmp_old_path, "xb") as stream:
                created = True
                stream.write(raw_bytes)
                stream.flush()
                os.fsync(stream.fileno())
            if self.decrypt_read_hook is not None:
                plain = self.decrypt_read_hook(tmp_old_path, raw_bytes)
            else:
                with open(tmp_old_path, "rb") as stream:
                    plain = stream.read()
            if (not isinstance(plain, bytes) or not plain
                    or plain.startswith(TSD_MAGIC_HEADER) or plain == raw_bytes):
                raise CorruptedCipherBlobError(f"DLP .old channel did not decrypt {hint_path}")
            return plain
        except CorruptedCipherBlobError:
            raise
        except Exception as exc:
            raise CorruptedCipherBlobError(f"DLP .old read failed for {hint_path}: {exc}") from exc
        finally:
            if created and os.path.lexists(tmp_old_path):
                os.remove(tmp_old_path)

    def _delta(self, old_tree_oid: str, new_tree_oid: str) -> List[dict]:
        delta = self.target_git.diff_tree_raw(old_tree_oid, new_tree_oid)
        for item in delta:
            if item["status"] not in ("A", "M", "T", "D"):
                raise MaterializeError(f"Unsupported delta status: {item['status']}")
            self._target_path(item["path"])
            for mode_key in ("old_mode", "new_mode"):
                mode = item[mode_key]
                if mode != "000000" and mode not in ALLOWED_SHARED_BLOB_MODES:
                    raise MaterializeError(f"Unsupported shared Git mode {mode}: {item['path']}")
        self._validate_directory_collapses(delta)
        return sorted(delta, key=lambda item: item["status"] != "D")

    def _validate_directory_collapses(self, delta: List[dict]) -> None:
        deletions = {item["path"] for item in delta if item["status"] == "D"}
        for item in delta:
            target = self._target_path(item["path"])
            if item["status"] == "D" or not os.path.isdir(target):
                continue
            for root, directories, files in os.walk(target, followlinks=False):
                for name in directories + files:
                    rel = os.path.relpath(os.path.join(root, name), self.target_worktree).replace(os.sep, "/")
                    checked = self._target_path(rel)
                    if not os.path.isdir(checked) and rel not in deletions:
                        raise MaterializeError(f"Untracked/non-deleted data blocks directory collapse: {rel}")

    @staticmethod
    def _summary(delta: List[dict]) -> Dict[str, int]:
        return {name: sum(item["status"] == status for item in delta)
                for name, status in (("added", "A"), ("modified", "M"),
                                     ("deleted", "D"), ("type_changed", "T"))}

    def prepare_transaction_staging(
        self, old_tree_oid: str, new_tree_oid: str, direction: Optional[str] = None,
        allow_dirty: bool = False,
    ) -> dict:
        direction = self._direction(direction or self.direction)
        if not allow_dirty and self.target_git.status_porcelain_z() != []:
            raise MaterializeError("Target worktree is dirty or contains untracked files")
        delta = self._delta(old_tree_oid, new_tree_oid)
        self._ensure_staging_dir()
        manifest_path = os.path.join(self.staging_dir, "manifest.json")
        if os.path.exists(manifest_path):
            raise MaterializeError("Transaction is already prepared; use a fresh tx_id")
        staged = os.path.join(self.staging_dir, "staged")
        rollback = os.path.join(self.staging_dir, "rollback")
        for directory in (staged, rollback):
            verify_no_worktree_reparse_points(self.target_worktree, os.path.relpath(
                directory, self.target_worktree).replace(os.sep, "/"))
            os.makedirs(directory, exist_ok=True)
        journal, operations = [], []
        for idx, item in enumerate(delta):
            entry = dict(item)
            target = self._target_path(item["path"])
            entry["target_abs_path"] = target
            if item["status"] in ("D", "M", "T"):
                with open(target, "rb") as stream:
                    backup_bytes = stream.read()
                backup_bytes = self.decrypt_blob_via_old_channel(backup_bytes, hint_path=item["path"])
                backup_path = os.path.join(rollback, f"{idx}_{item['old_oid']}.bak")
                _write_fsynced(backup_path, backup_bytes)
                entry.update(backup_path=backup_path, backup_size=len(backup_bytes),
                             backup_sha256=hashlib.sha256(backup_bytes).hexdigest())
            if item["status"] == "D":
                operation = {"mode": "DELETE_FILE", "target_abs_path": target}
            else:
                plain = self.decrypt_blob_via_old_channel(
                    self.target_git.cat_file_blob(item["new_oid"]),
                    expected_source_oid=item["new_oid"], hint_path=item["path"],
                )
                digest = hashlib.sha256(plain).hexdigest()
                stage_path = os.path.join(staged, f"{idx}_{digest}.old")
                _write_fsynced(stage_path, plain)
                operation = {"mode": "REPLACE_UNENCRYPTED", "stage_old_path": stage_path,
                             "target_abs_path": target, "expected_size": len(plain),
                             "expected_sha256": digest, "git_mode": item["new_mode"]}
                entry.update(stage_old_path=stage_path, expected_sha256=digest,
                             expected_size=len(plain))
            operation.update(path=item["path"], status=item["status"])
            operations.append(operation)
            journal.append(entry)
        nonce = secrets.token_hex(16)
        manifest = {"tx_id": self.tx_id, "nonce": nonce, "direction": direction,
                    "old_tree_oid": old_tree_oid, "new_tree_oid": new_tree_oid,
                    "target_worktree": self.target_worktree, "items": operations}
        for directory in (staged, rollback):
            _fsync_dir(directory)
        _write_json_atomic(manifest_path, manifest)
        # No target writes have occurred. Only this returned, fully durable journal
        # is eligible for the caller's WAL transition from preparing to prepared.
        info = {"tx_id": self.tx_id, "direction": direction, "nonce": nonce,
                "staging_dir": self.staging_dir, "manifest": manifest,
                "manifest_path": manifest_path, "worktree_journal": journal,
                "manifest_sha256": hashlib.sha256(self._read_bytes(manifest_path)).hexdigest()}
        self.last_staging_info = info
        return info

    @staticmethod
    def _read_bytes(path: str) -> bytes:
        with open(path, "rb") as stream:
            return stream.read()

    def materialize_delta(self, old_tree_oid: str, new_tree_oid: str) -> Dict[str, int]:
        if self.direction == "B2A":
            return self.materialize_delta_unencrypted_via_old(old_tree_oid, new_tree_oid)
        delta = self._delta(old_tree_oid, new_tree_oid)
        for item in delta:
            target = self._target_path(item["path"])
            if item["status"] == "D":
                self._safe_remove_file(target)
            else:
                self._prepare_parent(target)
                plain = self.decrypt_blob_via_old_channel(
                    self.target_git.cat_file_blob(item["new_oid"]), item["new_oid"], item["path"]
                )
                self._safe_write_bytes(target, plain, is_symlink=False)
                self._apply_mode(target, item["new_mode"])
        return self._summary(delta)

    def _prepare_parent(self, target: str) -> None:
        parent = os.path.dirname(target)
        # Only prune empty directories, never recursively remove untracked data.
        if os.path.isdir(target):
            try:
                os.rmdir(target)
            except OSError as exc:
                raise MaterializeError(f"Non-empty directory blocks file target: {target}") from exc
        os.makedirs(parent, exist_ok=True)
        self._target_path(os.path.relpath(target, self.target_worktree).replace(os.sep, "/"))

    @staticmethod
    def _apply_mode(target: str, mode: str) -> None:
        if not _IS_WINDOWS:
            os.chmod(target, 0o755 if mode == "100755" else 0o644)

    def materialize_delta_unencrypted_via_old(
        self, old_tree_oid: str, new_tree_oid: str, staging_info: Optional[dict] = None,
        lease_callback: Optional[Callable[[dict], None]] = None,
    ) -> Dict[str, int]:
        info = staging_info or self.prepare_transaction_staging(
            old_tree_oid, new_tree_oid, direction="B2A"
        )
        raw_manifest = self._read_bytes(info["manifest_path"])
        if hashlib.sha256(raw_manifest).hexdigest() != info["manifest_sha256"]:
            raise MaterializeError("Prepared manifest SHA-256 mismatch")
        manifest = json.loads(raw_manifest.decode("utf-8"))
        if (manifest["tx_id"] != self.tx_id or manifest["nonce"] != info["nonce"]
                or manifest["old_tree_oid"] != old_tree_oid
                or manifest["new_tree_oid"] != new_tree_oid
                or manifest["target_worktree"] != self.target_worktree):
            raise MaterializeError("Prepared staging belongs to a different transaction")
        self._validate_manifest(manifest)
        result = self._execute_manifest(manifest, lease_callback)
        self._assert_result(manifest, result)
        return self._summary(manifest["items"])

    def _validate_manifest(self, manifest: dict) -> None:
        for item in manifest["items"]:
            target = item["target_abs_path"]
            rel_path = os.path.relpath(target, self.target_worktree).replace(os.sep, "/")
            if os.path.normcase(self._target_path(rel_path)) != os.path.normcase(os.path.abspath(target)):
                raise MaterializeError("Manifest target escapes the worktree")
            if item["mode"] == "REPLACE_UNENCRYPTED":
                stage = os.path.abspath(item["stage_old_path"])
                if (os.path.commonpath([stage, self.staging_dir]) != self.staging_dir
                        or not stage.endswith(".old")):
                    raise MaterializeError("Replacement must originate in transaction .old staging")
                verify_no_worktree_reparse_points(self.target_worktree, os.path.relpath(
                    stage, self.target_worktree).replace(os.sep, "/"))
            elif item["mode"] not in ("DELETE_FILE", "PROBE_PHYSICAL_HEADER"):
                raise MaterializeError(f"Unsupported worker operation: {item['mode']}")

    @staticmethod
    def _assert_result(manifest: dict, result: dict) -> None:
        if not isinstance(result, dict) or result.get("overall_status") != "PASS":
            raise MaterializeError(f"Out-of-tree worker failed: {result}")
        if result.get("tx_id") != manifest["tx_id"] or result.get("nonce") != manifest["nonce"]:
            raise MaterializeError("Worker result transaction/nonce mismatch")
        if (len(result.get("items", [])) != len(manifest["items"])
                or any(item.get("status") != "PASS" for item in result["items"])):
            raise MaterializeError("Worker result does not attest every manifest item")

    def _execute_manifest(
        self, manifest: dict, lease_callback: Optional[Callable[[dict], None]] = None,
    ) -> dict:
        self._ensure_staging_dir()
        self._validate_manifest(manifest)
        intent = secrets.token_hex(16)
        lease_file = os.path.join(self.staging_dir, f"lease_active_{intent}.json")
        release_file = os.path.join(self.staging_dir, f"release_go_{intent}.flag")
        lease = {"intent_nonce": intent, "parent_pid": os.getpid(),
                 "parent_create_time_ft": get_current_proc_filetime(),
                 "worker_pid": None, "worker_create_time_ft": None, "state": "SPAWNING",
                 "lease_file": lease_file, "release_flag_file": release_file}
        self.last_executor_lease = lease.copy()
        # Persist intent before even calling an injected runner. The caller must
        # fsync its WAL in this callback; an exception prevents process creation.
        _write_json_atomic(lease_file, lease)
        try:
            if lease_callback:
                lease_callback(lease.copy())
            if self.unmonitored_runner:
                result = self.unmonitored_runner(manifest)
            elif _IS_WINDOWS:
                result = self._run_windows_worker(manifest, lease, lease_callback)
            else:
                result = self._run_posix_manifest(manifest)
            self._assert_result(manifest, result)
            return result
        except Exception:
            # Revoke first: even a not-yet-registered orphan cannot obtain release.
            if os.path.exists(lease_file):
                os.remove(lease_file)
            if lease.get("worker_pid"):
                terminate_lingering_worker(lease)
            raise
        finally:
            self.last_executor_lease = lease.copy()
            for path in (lease_file, release_file, lease_file + ".worker"):
                if os.path.exists(path):
                    os.remove(path)

    @staticmethod
    def _attestation(data: bytes) -> dict:
        return {"physical_size": len(data), "physical_sha256": hashlib.sha256(data).hexdigest(),
                "physical_header_hex": data[:16].hex(),
                "has_tsd_header": data.startswith(TSD_MAGIC_HEADER)}

    def _run_posix_manifest(self, manifest: dict) -> dict:
        result = {"tx_id": manifest["tx_id"], "nonce": manifest["nonce"],
                  "overall_status": "PASS", "failed_index": None, "error": None, "items": []}
        for idx, item in enumerate(manifest["items"]):
            observed = {"index": idx, "mode": item["mode"],
                        "target_abs_path": item["target_abs_path"], "status": "PASS"}
            try:
                target = item["target_abs_path"]
                self._target_path(os.path.relpath(target, self.target_worktree).replace(os.sep, "/"))
                if item["mode"] == "DELETE_FILE":
                    self._safe_remove_file(target)
                    if os.path.lexists(target):
                        raise MaterializeError("Deletion left a physical target behind")
                    observed["exists"] = False
                elif item["mode"] == "REPLACE_UNENCRYPTED":
                    before = self._read_bytes(item["stage_old_path"])
                    self._assert_plain_bytes(before, item)
                    self._prepare_parent(target)
                    os.replace(item["stage_old_path"], target)
                    self._apply_mode(target, item.get("git_mode", "100644"))
                    after = self._read_bytes(target)
                    self._assert_plain_bytes(after, item)
                    _fsync_dir(os.path.dirname(target))
                    observed.update(self._attestation(after))
                else:
                    data = self._read_bytes(target)
                    observed.update(self._attestation(data))
                    if item.get("include_bytes"):
                        observed["physical_bytes_base64"] = base64.b64encode(data).decode("ascii")
            except Exception as exc:
                observed.update(status="FAIL", error=str(exc))
                result.update(overall_status="FAIL", failed_index=idx, error=str(exc))
            result["items"].append(observed)
            if result["overall_status"] == "FAIL":
                break
        _write_json_atomic(os.path.join(self.staging_dir, f"result_{manifest['nonce']}.json"), result)
        return result

    @staticmethod
    def _assert_plain_bytes(data: bytes, item: dict) -> None:
        if (data.startswith(TSD_MAGIC_HEADER) or len(data) != int(item["expected_size"])
                or hashlib.sha256(data).hexdigest() != item["expected_sha256"]):
            raise MaterializeError("Physical plaintext size/SHA-256/header verification failed")

    def _spawn_windows_worker(self, command: List[str]) -> int:
        # WMI creates the writer OUTSIDE the monitored Python process tree. Only
        # a base64 command line crosses the launcher; paths are never interpolated
        # into PowerShell source, expanded through cmd.exe, or percent-expanded.
        encoded = base64.b64encode(subprocess.list2cmdline(command).encode("utf-8")).decode("ascii")
        launcher = ("$ErrorActionPreference='Stop';"
                    f"$c=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('{encoded}'));"
                    "$r=([WMIClass]'Win32_Process').Create($c);"
                    "if($r.ReturnValue -ne 0){throw ('Win32_Process.Create: '+$r.ReturnValue)};"
                    "[Console]::Out.Write($r.ProcessId)")
        output = subprocess.run(
            [command[0], "-NoProfile", "-NonInteractive", "-EncodedCommand",
             base64.b64encode(launcher.encode("utf-16le")).decode("ascii")],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        )
        return int(output.stdout.decode("ascii").strip())

    def _run_windows_worker(
        self, manifest: dict, lease: dict, lease_callback: Optional[Callable[[dict], None]],
    ) -> dict:
        manifest_path = os.path.join(self.staging_dir, f"worker_{lease['intent_nonce']}.old")
        result_path = manifest_path + ".result"
        _write_json_atomic(manifest_path, manifest)
        powershell = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                  "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
        command = [powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                   "-File", self.worker_script_path,
                   "-ManifestPath", manifest_path, "-ResultPath", result_path,
                   "-ParentPid", str(lease["parent_pid"]),
                   "-ParentCreateTimeFt", str(lease["parent_create_time_ft"]),
                   "-LeaseFile", lease["lease_file"], "-ReleaseFlagFile", lease["release_flag_file"]]
        worker_pid = self._spawn_windows_worker(command)
        deadline = time.monotonic() + 10
        registration = lease["lease_file"] + ".worker"
        while not os.path.isfile(registration):
            if time.monotonic() >= deadline:
                raise MaterializeError("Worker registration timed out; release was withheld")
            time.sleep(0.05)
        with open(registration, encoding="utf-8-sig") as stream:
            identity = json.load(stream)
        if int(identity["worker_pid"]) != worker_pid or int(identity["worker_create_time_ft"]) <= 0:
            raise MaterializeError("Worker registration does not match the spawned worker")
        lease.update(worker_pid=worker_pid,
                     worker_create_time_ft=int(identity["worker_create_time_ft"]), state="ACTIVE")
        _write_json_atomic(lease["lease_file"], lease)
        if lease_callback:
            lease_callback(lease.copy())
        _write_fsynced(lease["release_flag_file"], b"GO\n")
        _fsync_dir(self.staging_dir)
        deadline = time.monotonic() + self.worker_timeout
        while not os.path.isfile(result_path):
            if time.monotonic() >= deadline:
                raise MaterializeError("Worker execution timed out")
            time.sleep(0.05)
        with open(result_path, encoding="utf-8-sig") as stream:
            result = json.load(stream)
        # Result publication is its last file operation, but still wait for the
        # handle to signal before declaring that there can be no surviving writer.
        kernel = _windows_kernel32()
        handle = kernel.OpenProcess(0x1000 | 0x00100000, False, worker_pid)
        if handle:
            try:
                if (_process_filetime(kernel, handle) == lease["worker_create_time_ft"]
                        and kernel.WaitForSingleObject(handle, 10000) != 0):
                    raise MaterializeError("Worker published a result but did not exit")
            finally:
                kernel.CloseHandle(handle)
        elif ctypes.get_last_error() not in (87, 1168):
            raise MaterializeError("Cannot confirm worker exit")
        lease["state"] = "EXITED"
        return result

    def rollback_from_journal(
        self, worktree_journal: List[dict], direction: Optional[str] = None,
    ) -> None:
        direction = self._direction(direction or self.direction)
        backups = {}
        # Validate EVERY backup before changing anything; a partial preparing
        # journal must never be guessed into a usable rollback plan.
        for idx, entry in enumerate(worktree_journal):
            self._target_path(entry["path"])
            if entry["status"] == "A":
                continue
            if entry["status"] not in ("M", "T", "D"):
                raise MaterializeError("Invalid rollback journal status")
            backup = os.path.abspath(entry["backup_path"])
            rollback_root = os.path.join(self.staging_dir, "rollback")
            if os.path.commonpath([backup, rollback_root]) != rollback_root or not backup.endswith(".bak"):
                raise MaterializeError("Rollback backup is outside the transaction")
            verify_no_worktree_reparse_points(self.target_worktree, os.path.relpath(
                backup, self.target_worktree).replace(os.sep, "/"))
            data = self._read_bytes(backup)
            if (len(data) != entry["backup_size"]
                    or hashlib.sha256(data).hexdigest() != entry["backup_sha256"]
                    or data.startswith(TSD_MAGIC_HEADER)):
                raise MaterializeError("Rollback backup size/SHA-256/plaintext verification failed")
            backups[idx] = data
        # Undo additions before restoring deleted files (also handles directory
        # versus file transitions). Never consume .bak files: rollback is retryable.
        additions = [entry for entry in worktree_journal if entry["status"] == "A"]
        restores = [(idx, entry) for idx, entry in enumerate(worktree_journal)
                    if entry["status"] != "A"]
        if direction == "A2B":
            for entry in reversed(additions):
                self._safe_remove_file(self._target_path(entry["path"]))
            for idx, entry in restores:
                target = self._target_path(entry["path"])
                self._prepare_parent(target)
                self._safe_write_bytes(target, backups[idx], is_symlink=False)
                self._apply_mode(target, entry["old_mode"])
            return
        self._ensure_staging_dir()
        nonce = secrets.token_hex(16)
        operations = [{"mode": "DELETE_FILE", "target_abs_path": self._target_path(entry["path"])}
                      for entry in reversed(additions)]
        for idx, entry in restores:
            stage = os.path.join(self.staging_dir, f"rollback_{nonce}_{idx}.old")
            _write_fsynced(stage, backups[idx])
            operations.append({"mode": "REPLACE_UNENCRYPTED", "stage_old_path": stage,
                               "target_abs_path": self._target_path(entry["path"]),
                               "expected_size": len(backups[idx]),
                               "expected_sha256": entry["backup_sha256"],
                               "git_mode": entry["old_mode"]})
        manifest = {"tx_id": self.tx_id, "nonce": nonce, "items": operations,
                    "direction": "B2A", "target_worktree": self.target_worktree}
        self._assert_result(manifest, self._execute_manifest(manifest))

    def _safe_remove_file(self, abs_path: str) -> None:
        for attempt in range(len(self.lock_backoff) + 1):
            try:
                os.remove(abs_path)
                return
            except FileNotFoundError:
                return
            except OSError as exc:
                if attempt == len(self.lock_backoff):
                    raise MaterializeError(f"Failed to remove file '{abs_path}': {exc}") from exc
                time.sleep(self.lock_backoff[attempt])

    def _safe_write_bytes(self, abs_path: str, data: bytes, is_symlink: bool = False) -> None:
        # One attempt body, including the FINAL retry. There is no weaker fallback
        # that can return without the rb -> wb/fsync DLP-triggering rewrite.
        for attempt in range(len(self.lock_backoff) + 1):
            try:
                _write_fsynced(abs_path, data)
                if not is_symlink:
                    _write_fsynced(abs_path, self._read_bytes(abs_path))
                return
            except OSError as exc:
                if attempt == len(self.lock_backoff):
                    raise MaterializeError(f"Failed to write file '{abs_path}': {exc}") from exc
                time.sleep(self.lock_backoff[attempt])
