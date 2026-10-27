import hashlib
import re
from typing import Optional, Set

TSD_MAGIC_HEADER = b"%TSD-Header-###%"
NORMALIZER_SPEC_VERSION = "3.0"

BINARY_EXTENSIONS: Set[str] = {
    ".ko",
    ".so",
    ".a",
    ".o",
    ".bin",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".bmp",
    ".tar.gz",
    ".tgz",
    ".zip",
    ".7z",
    ".ttf",
    ".otf",
    ".pdf",
    ".elf",
    ".img",
    ".docx",
    ".xlsx",
    ".pptx",
}

LF_REQUIRED_BASENAMES: Set[str] = {"Makefile", "cfg.mk", ".gitignore"}
LF_REQUIRED_EXTENSIONS: Set[str] = {".sh", ".mk", ".py", ".awk"}

_CR_PLUS_LF_RE = re.compile(rb"\r+\n")


def normalize_lf_idempotent(data: bytes) -> bytes:
    """
    Unconditionally idempotent CRLF-to-LF normalizer:
    Collapses any run of one or more '\\r' followed by '\\n' into a single '\\n'.
    Satisfies normalize_lf_idempotent(normalize_lf_idempotent(x)) == normalize_lf_idempotent(x)
    for all byte strings x (including b'A\\r\\r\\nB' -> b'A\\nB').
    """
    return _CR_PLUS_LF_RE.sub(b"\n", data)


class ContentNormalizer:
    """
    Contract 2 content classifier, canonical digest computer, and Git store normalizer.
    """

    def __init__(self) -> None:
        self._lf_basenames_lower = {b.lower() for b in LF_REQUIRED_BASENAMES}

    def classify_blob_kind(self, rel_path: str, plain_bytes: bytes) -> str:
        """
        Classifies a blob into 'BINARY', 'TEXT_LF_REQUIRED', or 'TEXT_GENERAL'
        according to Section 3.1 of the v3.0 design specification.
        """
        basename = rel_path.replace("\\", "/").split("/")[-1]
        lower_base = basename.lower()

        if any(lower_base.endswith(ext) for ext in BINARY_EXTENSIONS):
            return "BINARY"

        if b"\x00" in plain_bytes[:8192]:
            return "BINARY"

        if (
            basename in LF_REQUIRED_BASENAMES
            or lower_base in self._lf_basenames_lower
            or any(lower_base.endswith(ext) for ext in LF_REQUIRED_EXTENSIONS)
        ):
            return "TEXT_LF_REQUIRED"

        try:
            plain_bytes.decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            try:
                plain_bytes.decode("gb18030", errors="strict")
            except UnicodeDecodeError:
                return "BINARY"

        return "TEXT_GENERAL"

    def canon_hash(self, rel_path: str, plain_bytes: bytes) -> str:
        """
        Computes type-dispatched canonical hash:
        - 'bin:<sha256(plain_bytes)>' for BINARY
        - 'txt:<sha256(normalize_lf_idempotent(plain_bytes))>' for TEXT_LF_REQUIRED and TEXT_GENERAL
        """
        kind = self.classify_blob_kind(rel_path, plain_bytes)
        if kind == "BINARY":
            digest = hashlib.sha256(plain_bytes).hexdigest()
            return f"bin:{digest}"

        norm_bytes = normalize_lf_idempotent(plain_bytes)
        digest = hashlib.sha256(norm_bytes).hexdigest()
        return f"txt:{digest}"

    def normalize_for_repo_a(
        self,
        rel_path: str,
        plain_bytes: bytes,
        baseline_a_bytes: Optional[bytes] = None,
    ) -> bytes:
        """
        Normalizes decrypted plaintext bytes from Repo B before writing into Repo A (B -> A):
        - BINARY: identity (plain_bytes unchanged)
        - TEXT_LF_REQUIRED: normalize_lf_idempotent(plain_bytes)
        - TEXT_GENERAL: normalize_lf_idempotent(plain_bytes), or CRLF if baseline_a_bytes uses CRLF
        """
        kind = self.classify_blob_kind(rel_path, plain_bytes)
        if kind == "BINARY":
            return plain_bytes

        lf_bytes = normalize_lf_idempotent(plain_bytes)
        if kind == "TEXT_LF_REQUIRED":
            return lf_bytes

        if baseline_a_bytes is not None and b"\r\n" in baseline_a_bytes:
            return lf_bytes.replace(b"\n", b"\r\n")
        return lf_bytes

    def normalize_for_git_store(
        self,
        direction: str,
        rel_path: str,
        plain_bytes: bytes,
        baseline_a_bytes: Optional[bytes] = None,
    ) -> bytes:
        """
        Normalizes bytes for Git object storage in either direction ('A2B' or 'B2A').
        """
        dir_norm = (direction or "").upper().strip()
        if dir_norm in ("B2A", "B->A", "B_TO_A", "REVERSE", "REPO_A"):
            return self.normalize_for_repo_a(
                rel_path, plain_bytes, baseline_a_bytes=baseline_a_bytes
            )

        # Forward direction (A -> B)
        kind = self.classify_blob_kind(rel_path, plain_bytes)
        if kind == "BINARY":
            return plain_bytes
        if kind == "TEXT_LF_REQUIRED":
            return normalize_lf_idempotent(plain_bytes)
        return plain_bytes
