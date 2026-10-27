"""Kernel-backed, non-blocking process locks for synchronization transactions."""

import json
import os
import time
import uuid
from datetime import datetime, timezone
from typing import Optional


class LockBusyError(Exception):
    pass


def _monotonic_ns() -> int:
    # Python 3.6 compatibility; newer runtimes use their native ns clocks.
    if hasattr(time, "monotonic_ns"):
        return time.monotonic_ns()
    return int(time.monotonic() * 1_000_000_000)


def _time_ns() -> int:
    if hasattr(time, "time_ns"):
        return time.time_ns()
    return int(time.time() * 1_000_000_000)


def generate_tx_id(repo_id: str, direction: str = "SYNC") -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"tx_{timestamp}_{_monotonic_ns()}_{uuid.uuid4().hex[:12]}_{repo_id}_{direction}"


class ProcessLock:
    def __init__(self, lock_file_path: str):
        self.lock_file_path = lock_file_path
        self.fd: Optional[int] = None

    def acquire(self, tx_id: str = "") -> None:
        if self.fd is not None:
            raise LockBusyError(f"Lock already acquired: '{self.lock_file_path}'")

        # Never truncate before acquiring the kernel lock: contenders must not
        # overwrite the current owner's diagnostic metadata.
        fd = os.open(self.lock_file_path, os.O_CREAT | os.O_RDWR, 0o644)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:  # Includes BlockingIOError and IOError.
            os.close(fd)
            raise LockBusyError(f"Lock is busy: '{self.lock_file_path}'") from exc
        except BaseException:
            os.close(fd)
            raise

        try:
            metadata = json.dumps({
                "pid": os.getpid(),
                "time_ns": _time_ns(),
                "tx_id": tx_id,
            }).encode("utf-8")
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            remaining = memoryview(metadata)
            while remaining:
                written = os.write(fd, remaining)
                if written <= 0:
                    raise OSError("Failed to write lock metadata")
                remaining = remaining[written:]
            os.fsync(fd)
        except BaseException:
            # Closing the descriptor also releases its kernel lock if writing
            # or syncing diagnostic metadata fails.
            os.close(fd)
            raise

        self.fd = fd

    def release(self) -> None:
        if self.fd is None:
            return

        fd = self.fd
        self.fd = None
        try:
            if os.name == "nt":
                import msvcrt

                # msvcrt locks relative to the current file offset, which the
                # metadata write has advanced beyond the locked first byte.
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)
        # Do not unlink the file: every contender must lock the same inode.

    def __enter__(self) -> "ProcessLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.release()
