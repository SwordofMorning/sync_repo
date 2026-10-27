import os
import shutil
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine.content_normalizer import (
    BINARY_EXTENSIONS,
    LF_REQUIRED_BASENAMES,
    LF_REQUIRED_EXTENSIONS,
    NORMALIZER_SPEC_VERSION,
    TSD_MAGIC_HEADER,
    ContentNormalizer,
    normalize_lf_idempotent,
)
from engine.path_validator import (
    ALLOWED_SHARED_BLOB_MODES,
    ALLOWED_SHARED_MODES,
    FORBIDDEN_PATH_CHARS,
    WINDOWS_RESERVED_STEMS,
    CaseFoldedNamespaceTrie,
    NamespaceCollisionError,
    PathValidationError,
    collect_ancestor_dirs,
    validate_platform_rel_path,
    verify_no_worktree_reparse_points,
)


class TestPathValidatorAndTrie(unittest.TestCase):
    def test_valid_paths_and_ancestors(self):
        validate_platform_rel_path("app/mickey_smart/Makefile")
        validate_platform_rel_path("docs/readme.md")
        validate_platform_rel_path("Makefile")
        self.assertEqual(
            collect_ancestor_dirs("app/mickey_smart/src/main.c"),
            ["app", "app/mickey_smart", "app/mickey_smart/src"],
        )
        self.assertEqual(collect_ancestor_dirs("Makefile"), [])

    def test_at2_03_forbidden_chars_and_windows_reserved_stems(self):
        for bad_ch in ['\\', ':', '\x00', '<', '>', '"', '|', '?', '*']:
            with self.assertRaises(PathValidationError):
                validate_platform_rel_path(f"tools/a{bad_ch}b.c")

        # Control characters
        with self.assertRaises(PathValidationError):
            validate_platform_rel_path("tools/a\x1fb.c")

        # Traversal, empty, trailing dot/space
        for bad_path in [
            "",
            "/leading/slash.c",
            "trailing/slash/",
            "double//slash.c",
            "docs/../secret.c",
            "docs/./a.c",
            "docs/trailing_dot./a.c",
            "docs/trailing_space /a.c",
        ]:
            with self.assertRaises(PathValidationError):
                validate_platform_rel_path(bad_path)

        # Windows reserved device stems (case-insensitive, with or without extension)
        for reserved in ["CON", "prn.txt", "Aux.c", "nul", "COM1.log", "lpt9.dat", "CLOCK$"]:
            with self.assertRaises(PathValidationError):
                validate_platform_rel_path(f"docs/{reserved}")

    def test_at2_03_case_folded_namespace_trie_collisions(self):
        # 1. Counterexample from RR2-03: Repo A has private file 'docs/pkg.docx',
        #    Repo B adds 'docs/PKG.DOCX/new.c' -> caught at component 'pkg.docx'
        trie = CaseFoldedNamespaceTrie()
        trie.insert_path("docs/pkg.docx", origin_tag="PRIVATE")
        with self.assertRaises(NamespaceCollisionError):
            trie.insert_path("docs/PKG.DOCX/new.c", origin_tag="SHARED")

        # Reverse insertion order also caught
        trie2 = CaseFoldedNamespaceTrie()
        trie2.insert_path("docs/PKG.DOCX/new.c", origin_tag="SHARED")
        with self.assertRaises(NamespaceCollisionError):
            trie2.insert_path("docs/pkg.docx", origin_tag="PRIVATE")

        # 2. Same-case file vs directory conflict
        trie3 = CaseFoldedNamespaceTrie()
        trie3.insert_path("docs/pkg.docx", origin_tag="PRIVATE")
        with self.assertRaises(NamespaceCollisionError):
            trie3.insert_path("docs/pkg.docx/new.c", origin_tag="SHARED")

        # 3. Case-alias leaf collision
        trie4 = CaseFoldedNamespaceTrie()
        trie4.insert_path("app/mickey_smart/Main.c", origin_tag="SHARED")
        with self.assertRaises(NamespaceCollisionError):
            trie4.insert_path("app/mickey_smart/main.c", origin_tag="SHARED")

        # 4. Duplicate leaf insertion
        trie5 = CaseFoldedNamespaceTrie()
        trie5.insert_path("app/mickey_smart/main.c", origin_tag="PRIVATE")
        with self.assertRaises(NamespaceCollisionError):
            trie5.insert_path("app/mickey_smart/main.c", origin_tag="SHARED")

    def test_verify_no_worktree_reparse_points(self):
        workspace_root = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..", "..")
        )
        test_tmp = os.path.join(workspace_root, ".playground", "test_reparse_tmp")
        shutil.rmtree(test_tmp, ignore_errors=True)
        os.makedirs(os.path.join(test_tmp, "real_dir"), exist_ok=True)
        try:
            verify_no_worktree_reparse_points(test_tmp, "real_dir/nonexistent_child.c")
            link_path = os.path.join(test_tmp, "sym_dir")
            os.symlink(os.path.join(test_tmp, "real_dir"), link_path)
            with self.assertRaises(PathValidationError):
                verify_no_worktree_reparse_points(test_tmp, "sym_dir/file.c")
        finally:
            shutil.rmtree(test_tmp, ignore_errors=True)


class TestContentNormalizer(unittest.TestCase):
    def setUp(self):
        self.normalizer = ContentNormalizer()

    def test_constants_defined(self):
        self.assertEqual(TSD_MAGIC_HEADER, b"%TSD-Header-###%")
        self.assertEqual(NORMALIZER_SPEC_VERSION, "3.0")
        self.assertIn(".ko", BINARY_EXTENSIONS)
        self.assertIn("Makefile", LF_REQUIRED_BASENAMES)
        self.assertIn(".sh", LF_REQUIRED_EXTENSIONS)
        self.assertEqual(ALLOWED_SHARED_BLOB_MODES, {"100644", "100755"})
        self.assertEqual(ALLOWED_SHARED_MODES, {"100644", "100755", "040000"})
        self.assertIn("CON", WINDOWS_RESERVED_STEMS)
        self.assertIn(":", FORBIDDEN_PATH_CHARS)

    def test_at2_04_idempotent_lf_normalization(self):
        # Single-pass collapse of \r+\n -> \n and strict idempotency on b"A\r\r\nB"
        raw = b"A\r\r\nB\r\r\r\nC\r\nD\nE"
        once = normalize_lf_idempotent(raw)
        twice = normalize_lf_idempotent(once)
        self.assertEqual(once, b"A\nB\nC\nD\nE")
        self.assertEqual(twice, once)

    def test_at2_04_binary_vs_text_canon_hash(self):
        # Binary files differing only in \r\n vs \n MUST have distinct CanonHash
        bin_crlf = b"\x00A\r\nB"
        bin_lf = b"\x00A\nB"
        h_bin_crlf = self.normalizer.canon_hash("firmware/image.dat", bin_crlf)
        h_bin_lf = self.normalizer.canon_hash("firmware/image.dat", bin_lf)
        self.assertTrue(h_bin_crlf.startswith("bin:"))
        self.assertTrue(h_bin_lf.startswith("bin:"))
        self.assertNotEqual(h_bin_crlf, h_bin_lf)

        # Extension-based binary without NUL bytes also preserves exact bytes
        ko_crlf = b"ELF_HEADER_MOCK\r\nDATA"
        ko_lf = b"ELF_HEADER_MOCK\nDATA"
        self.assertNotEqual(
            self.normalizer.canon_hash("driver/sensor.ko", ko_crlf),
            self.normalizer.canon_hash("driver/sensor.ko", ko_lf),
        )

        # Text files with \r\r\n, \r\n, and \n converge to the exact same CanonHash
        h_txt_1 = self.normalizer.canon_hash("app/mickey_smart/main.c", b"A\r\r\nB")
        h_txt_2 = self.normalizer.canon_hash("app/mickey_smart/main.c", b"A\r\nB")
        h_txt_3 = self.normalizer.canon_hash("app/mickey_smart/main.c", b"A\nB")
        self.assertTrue(h_txt_1.startswith("txt:"))
        self.assertEqual(h_txt_1, h_txt_2)
        self.assertEqual(h_txt_2, h_txt_3)

    def test_classify_and_normalize_for_git_store(self):
        self.assertEqual(
            self.normalizer.classify_blob_kind("scripts/build.sh", b"#!/bin/sh\r\necho hi\r\n"),
            "TEXT_LF_REQUIRED",
        )
        self.assertEqual(
            self.normalizer.classify_blob_kind("Makefile", b"all:\r\n\techo ok\r\n"),
            "TEXT_LF_REQUIRED",
        )
        self.assertEqual(
            self.normalizer.classify_blob_kind("app/mickey_smart/main.c", b"int a = 1;\r\n"),
            "TEXT_GENERAL",
        )

        # TEXT_LF_REQUIRED forces LF in both A2B and B2A even if baseline had CRLF
        sh_crlf = b"#!/bin/sh\r\r\necho 1\r\n"
        self.assertEqual(
            self.normalizer.normalize_for_git_store("A2B", "scripts/build.sh", sh_crlf),
            b"#!/bin/sh\necho 1\n",
        )
        self.assertEqual(
            self.normalizer.normalize_for_git_store(
                "B2A", "scripts/build.sh", sh_crlf, baseline_a_bytes=b"#!/bin/sh\r\n"
            ),
            b"#!/bin/sh\necho 1\n",
        )

        # TEXT_GENERAL in B2A defaults to LF unless baseline_a_bytes uses CRLF
        c_crlf = b"int x = 1;\r\nint y = 2;\r\n"
        self.assertEqual(
            self.normalizer.normalize_for_repo_a("app/mickey_smart/main.c", c_crlf),
            b"int x = 1;\nint y = 2;\n",
        )
        self.assertEqual(
            self.normalizer.normalize_for_repo_a(
                "app/mickey_smart/main.c",
                b"int x = 1;\nint y = 2;\n",
                baseline_a_bytes=b"int x = 0;\r\n",
            ),
            b"int x = 1;\r\nint y = 2;\r\n",
        )


if __name__ == "__main__":
    unittest.main()
