import os
from typing import Dict, List, Set

WINDOWS_RESERVED_STEMS: Set[str] = (
    {"CON", "PRN", "AUX", "NUL", "CLOCK$"}
    | {f"COM{i}" for i in range(1, 10)}
    | {f"LPT{i}" for i in range(1, 10)}
)

FORBIDDEN_PATH_CHARS: Set[str] = set('\\:\x00<>"|?*')

ALLOWED_SHARED_BLOB_MODES: Set[str] = {"100644", "100755"}
ALLOWED_SHARED_MODES: Set[str] = {"100644", "100755", "040000"}

FILE_ATTRIBUTE_REPARSE_POINT = 0x400


class PathValidationError(Exception):
    pass


class NamespaceCollisionError(Exception):
    pass


def validate_platform_rel_path(rel_path: str) -> None:
    """
    Validates that rel_path is a safe, cross-platform relative path suitable for
    both Linux and Windows worktrees. Raises PathValidationError on any violation.
    """
    if not isinstance(rel_path, str) or not rel_path:
        raise PathValidationError("Relative path must be a non-empty string")

    try:
        rel_path.encode("utf-8", errors="strict")
    except UnicodeEncodeError as e:
        raise PathValidationError(f"Path contains invalid UTF-8 surrogate characters: {e}")

    for ch in rel_path:
        if ch in FORBIDDEN_PATH_CHARS:
            raise PathValidationError(f"Forbidden character {ch!r} in path '{rel_path}'")
        if ord(ch) < 32:
            raise PathValidationError(
                f"ASCII control character (0x{ord(ch):02x}) in path '{rel_path}'"
            )

    parts = rel_path.split("/")
    for part in parts:
        if not part:
            raise PathValidationError(f"Empty path component in '{rel_path}'")
        if part in (".", ".."):
            raise PathValidationError(f"Traversal component '{part}' in path '{rel_path}'")
        if part.endswith(".") or part.endswith(" "):
            raise PathValidationError(
                f"Component '{part}' ends with trailing dot or space in path '{rel_path}'"
            )
        stem = part.split(".", 1)[0].upper()
        if stem in WINDOWS_RESERVED_STEMS:
            raise PathValidationError(
                f"Windows reserved device name '{part}' (stem='{stem}') in path '{rel_path}'"
            )


def collect_ancestor_dirs(rel_path: str) -> List[str]:
    """
    Returns ordered ancestor directory prefixes from top-most to immediate parent.
    For example, 'a/b/c.txt' -> ['a', 'a/b'].
    """
    if not rel_path:
        return []
    parts = rel_path.split("/")
    return ["/".join(parts[:i]) for i in range(1, len(parts))]


class CaseFoldedNamespaceTrie:
    """
    Enforces Windows case-insensitive filesystem representability and prevents any
    directory/file prefix or case-alias collision across private and shared entries.
    """

    def __init__(self) -> None:
        # Node structure: {"cased_name": str, "kind": "DIR"|"LEAF", "origins": set, "children": dict}
        self.root: Dict[str, object] = {
            "cased_name": "",
            "kind": "DIR",
            "origins": set(),
            "children": {},
        }

    def insert_path(self, rel_path: str, origin_tag: str = "SHARED") -> None:
        if not isinstance(rel_path, str) or not rel_path:
            raise NamespaceCollisionError(f"Invalid empty path for trie insertion: {rel_path!r}")
        parts = rel_path.split("/")
        if any(not p for p in parts):
            raise NamespaceCollisionError(f"Empty path component in '{rel_path}'")

        cur = self.root
        for idx, part in enumerate(parts):
            is_last = idx == len(parts) - 1
            expected_kind = "LEAF" if is_last else "DIR"
            key_lower = part.lower()
            prefix_so_far = "/".join(parts[: idx + 1])
            children: dict = cur["children"]  # type: ignore[assignment]

            if key_lower not in children:
                children[key_lower] = {
                    "cased_name": part,
                    "kind": expected_kind,
                    "origins": {origin_tag},
                    "children": {},
                }
                cur = children[key_lower]
            else:
                node = children[key_lower]
                # 1. Case-alias collision check (e.g., 'pkg.docx' vs 'PKG.DOCX')
                if node["cased_name"] != part:
                    raise NamespaceCollisionError(
                        f"Case-insensitive component collision at '{prefix_so_far}': "
                        f"'{part}' ({origin_tag}) collides with existing '{node['cased_name']}' ({node['origins']})"
                    )
                # 2. File vs Directory structural conflict check (e.g., file 'pkg.docx' vs dir 'pkg.docx/new.c')
                if node["kind"] != expected_kind:
                    raise NamespaceCollisionError(
                        f"File/Directory structural conflict at '{prefix_so_far}': "
                        f"attempted '{expected_kind}' ({origin_tag}) but already exists as '{node['kind']}' ({node['origins']})"
                    )
                # 3. Duplicate leaf insertion check
                if is_last and expected_kind == "LEAF":
                    raise NamespaceCollisionError(
                        f"Duplicate leaf path '{rel_path}' between {origin_tag} and {node['origins']}"
                    )
                node["origins"].add(origin_tag)
                cur = node


def _is_reparse_or_symlink(path: str) -> bool:
    if not os.path.lexists(path):
        return False
    if os.path.islink(path):
        return True
    try:
        st = os.lstat(path)
        if getattr(st, "st_file_attributes", 0) & FILE_ATTRIBUTE_REPARSE_POINT != 0:
            return True
    except OSError:
        return True
    return False


def verify_no_worktree_reparse_points(worktree_root: str, rel_path: str) -> None:
    """
    Walks from worktree_root through each existing ancestor component up to rel_path,
    raising PathValidationError if any component is a symlink or Windows reparse point.
    """
    cur = os.path.abspath(worktree_root)
    if _is_reparse_or_symlink(cur):
        raise PathValidationError(f"Worktree root is a symlink or reparse point: {cur}")

    if not rel_path:
        return

    parts = [p for p in rel_path.replace("\\", "/").split("/") if p]
    for part in parts:
        cur = os.path.join(cur, part)
        if not os.path.lexists(cur):
            continue
        if _is_reparse_or_symlink(cur):
            raise PathValidationError(
                f"Reparse point or symlink detected in worktree path: {cur}"
            )
