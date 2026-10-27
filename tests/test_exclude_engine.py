import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine.config_loader import SyncConfig
from engine.content_normalizer import ContentNormalizer
from engine.exclude_engine import ExcludeDecision, ExcludeEngine


class _FakeGitAdapter:
    def __init__(self, entries, blobs):
        self._entries = entries
        self._blobs = blobs

    def ls_tree_r_z(self, tree_oid: str):
        return self._entries.get(tree_oid, [])

    def cat_file_blob(self, blob_oid: str) -> bytes:
        return self._blobs[blob_oid]


class TestExcludeEngine(unittest.TestCase):
    def setUp(self):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.config = SyncConfig(base_dir)
        repo_smart = self.config.get_repo("smart")
        self.engine = ExcludeEngine(repo_smart["manifest"], repo_smart["exclude_rules"])

    def test_non_mickey_apps_pruned(self):
        dec, rule_id, _ = self.engine.evaluate_path("app/DOT/Makefile")
        self.assertEqual(dec, ExcludeDecision.PRUNE)

        dec, rule_id, _ = self.engine.evaluate_path("app/victory/main.c")
        self.assertEqual(dec, ExcludeDecision.PRUNE)

    def test_mickey_smart_allowed(self):
        dec, rule_id, _ = self.engine.evaluate_path("app/mickey_smart/Makefile")
        self.assertEqual(dec, ExcludeDecision.ALLOW)

        dec, rule_id, _ = self.engine.evaluate_path("app/mickey_smart/modules/init/main.c")
        self.assertEqual(dec, ExcludeDecision.ALLOW)

        dec, rule_id, _ = self.engine.evaluate_path("app/Makefile")
        self.assertEqual(dec, ExcludeDecision.ALLOW)

    def test_gwp_debug_pruned(self):
        dec, rule_id, _ = self.engine.evaluate_path("gwp_debug/strings2.0.xml")
        self.assertEqual(dec, ExcludeDecision.PRUNE)

    def test_internal_docs_pruned(self):
        dec, rule_id, _ = self.engine.evaluate_path("docs/hi3556烧录/分区镜像及SN号烧录说明.docx")
        self.assertEqual(dec, ExcludeDecision.PRUNE)

    def test_approved_dependency_exceptions_exact_match_and_mode(self):
        # Build and packaging archives MUST be ALLOWED on exact match with regular/exec mode
        dec, rule_id, _ = self.engine.evaluate_path("thirdparty/ffmpeg/FFmpeg-release-7.0.tar.gz")
        self.assertEqual(dec, ExcludeDecision.ALLOW)
        self.assertEqual(rule_id, "APPROVED_DEPENDENCY_EXCEPTION")

        dec, rule_id, _ = self.engine.evaluate_path("tools/package/app.tar.gz")
        self.assertEqual(dec, ExcludeDecision.ALLOW)

        dec, rule_id, _ = self.engine.evaluate_path(
            "tools/package/rootfs/lib/libasan_preinit.o", mode="100755"
        )
        self.assertEqual(dec, ExcludeDecision.ALLOW)

        # Case-mismatch on approved_dependency_exceptions must NOT match exception -> BLOCK_REVIEW
        dec, rule_id, _ = self.engine.evaluate_path("tools/package/APP.TAR.GZ")
        self.assertEqual(dec, ExcludeDecision.BLOCK_REVIEW)
        self.assertEqual(rule_id, "BLOCK_UNAPPROVED_ARCHIVES")

        # Symlink mode on approved dependency exception path must be blocked
        dec, rule_id, _ = self.engine.evaluate_path("tools/package/app.tar.gz", mode="120000")
        self.assertEqual(dec, ExcludeDecision.BLOCK_REVIEW)

    def test_unapproved_archives_and_keys_blocked(self):
        dec, rule_id, _ = self.engine.evaluate_path("component/suspicious.zip")
        self.assertEqual(dec, ExcludeDecision.BLOCK_REVIEW)

        dec, rule_id, _ = self.engine.evaluate_path("component/server.pem")
        self.assertEqual(dec, ExcludeDecision.BLOCK_REVIEW)

        # Case-insensitive pattern matching
        dec, rule_id, _ = self.engine.evaluate_path("component/SERVER.PEM")
        self.assertEqual(dec, ExcludeDecision.BLOCK_REVIEW)

    def test_at2_02_ancestor_accumulated_mode_and_platform_checks(self):
        # 1. Ancestor matching FILENAME prune rule: docs/pkg.docx/readme.md -> PRUNE
        dec, rule_id, _ = self.engine.evaluate_path("docs/pkg.docx/readme.md")
        self.assertEqual(dec, ExcludeDecision.PRUNE)
        self.assertEqual(rule_id, "PRUNE_INTERNAL_DOCS")

        # 2. Ancestor matching FILENAME block rule: docs/secret.pem/a.c -> BLOCK_REVIEW
        dec, rule_id, _ = self.engine.evaluate_path("docs/secret.pem/a.c")
        self.assertEqual(dec, ExcludeDecision.BLOCK_REVIEW)
        self.assertEqual(rule_id, "BLOCK_SUSPECTED_CREDENTIALS")

        # 3. Forbidden platform character in shared domain: tools/a:b.c -> BLOCK_REVIEW
        dec, rule_id, _ = self.engine.evaluate_path("tools/a:b.c")
        self.assertEqual(dec, ExcludeDecision.BLOCK_REVIEW)
        self.assertEqual(rule_id, "INVALID_PLATFORM_PATH")

        # 4. Forbidden platform character in PRUNE domain: gwp_debug/a:b.c -> PRUNE
        dec, rule_id, _ = self.engine.evaluate_path("gwp_debug/a:b.c")
        self.assertEqual(dec, ExcludeDecision.PRUNE)

        # 5. Unsupported git modes in shared domain: 120000 symlink & 160000 gitlink -> BLOCK_REVIEW
        dec, rule_id, _ = self.engine.evaluate_path("tools/run_link.sh", mode="120000")
        self.assertEqual(dec, ExcludeDecision.BLOCK_REVIEW)
        self.assertEqual(rule_id, "UNSUPPORTED_SHARED_GIT_MODE")

        dec, rule_id, _ = self.engine.evaluate_path("thirdparty/submod", mode="160000")
        self.assertEqual(dec, ExcludeDecision.BLOCK_REVIEW)
        self.assertEqual(rule_id, "UNSUPPORTED_SHARED_GIT_MODE")

        # 6. Symlink in PRUNE domain remains PRUNE, gitlink in PRUNE domain is BLOCK_REVIEW
        dec, rule_id, _ = self.engine.evaluate_path("app/DOT/link.so", mode="120000")
        self.assertEqual(dec, ExcludeDecision.PRUNE)

        dec, rule_id, _ = self.engine.evaluate_path("app/DOT/submod", mode="160000")
        self.assertEqual(dec, ExcludeDecision.BLOCK_REVIEW)
        self.assertEqual(rule_id, "UNSUPPORTED_SHARED_GIT_MODE")

    def test_content_scanner_ip_and_email(self):
        # 1. Private internal IP in core code -> Block
        bad_code = b'int connect() { return connect_to("10.42.0.252"); }\n'
        passed, name, hint = self.engine.scan_content_blob(
            "app/mickey_smart/src/net.c", bad_code
        )
        self.assertFalse(passed)
        self.assertEqual(name, "internal_ip_leak")

        # 2. Private developer email in core code -> Block
        bad_email = b"// Author: developer@gmail.com\n"
        passed, name, hint = self.engine.scan_content_blob(
            "app/mickey_smart/src/net.c", bad_email
        )
        self.assertFalse(passed)
        self.assertEqual(name, "personal_email_leak")

        # 3. Third-party copyright header -> Exempted
        copyright_header = b"/* Copyright (C) 2012 author@gmail.com */\n"
        passed, name, hint = self.engine.scan_content_blob(
            "include/libavutil/audio_fifo.h", copyright_header
        )
        self.assertTrue(passed)

    def test_at2_09_validate_export_tree_and_shared_norm(self):
        normalizer = ContentNormalizer()
        blobs = {
            "oid_main_lf": b"int main() {\n    return 0;\n}\n",
            "oid_main_crlf": b"int main() {\r\n    return 0;\r\n}\r\n",
            "oid_docx": b"PK\x03\x04private docx bytes",
            "oid_ip_leak": b'const char *ip = "10.42.0.252";\n',
        }
        entries = {
            "tree_a": [
                {"mode": "100644", "type": "blob", "oid": "oid_main_lf", "path": "app/mickey_smart/main.c"},
                {"mode": "100644", "type": "blob", "oid": "oid_docx", "path": "docs/private.docx"},
            ],
            "tree_b_clean": [
                {"mode": "100644", "type": "blob", "oid": "oid_main_crlf", "path": "app/mickey_smart/main.c"},
            ],
            "tree_b_polluted_prune": [
                {"mode": "100644", "type": "blob", "oid": "oid_main_crlf", "path": "app/mickey_smart/main.c"},
                {"mode": "100644", "type": "blob", "oid": "oid_docx", "path": "docs/private.docx"},
            ],
            "tree_b_polluted_ip": [
                {"mode": "100644", "type": "blob", "oid": "oid_ip_leak", "path": "app/mickey_smart/main.c"},
            ],
        }
        git = _FakeGitAdapter(entries, blobs)

        # SharedNorm of tree_a and tree_b_polluted_prune are equal because PRUNE paths are filtered
        norm_a = self.engine.compute_shared_norm(git, "tree_a", normalizer)
        norm_b_clean = self.engine.compute_shared_norm(git, "tree_b_clean", normalizer)
        norm_b_polluted = self.engine.compute_shared_norm(git, "tree_b_polluted_prune", normalizer)
        self.assertEqual(norm_a, norm_b_clean)
        self.assertEqual(norm_a, norm_b_polluted)

        # ValidateExportTree passes clean tree_b_clean
        ok, msg = self.engine.validate_export_tree(git, "tree_b_clean")
        self.assertTrue(ok, msg)

        # ValidateExportTree rejects tree_b_polluted_prune containing docs/private.docx
        ok, msg = self.engine.validate_export_tree(git, "tree_b_polluted_prune")
        self.assertFalse(ok)
        self.assertIn("docs/private.docx", msg)

        # ValidateExportTree rejects tree_b_polluted_ip containing internal IP leak
        ok, msg = self.engine.validate_export_tree(git, "tree_b_polluted_ip")
        self.assertFalse(ok)
        self.assertIn("internal_ip_leak", msg)


if __name__ == "__main__":
    unittest.main()
