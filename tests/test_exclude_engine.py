import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine.config_loader import SyncConfig
from engine.exclude_engine import ExcludeEngine, ExcludeDecision

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

    def test_approved_dependency_exceptions(self):
        # Build and packaging archives MUST be ALLOWED
        dec, rule_id, _ = self.engine.evaluate_path("thirdparty/ffmpeg/FFmpeg-release-7.0.tar.gz")
        self.assertEqual(dec, ExcludeDecision.ALLOW)
        self.assertEqual(rule_id, "APPROVED_DEPENDENCY_EXCEPTION")

        dec, rule_id, _ = self.engine.evaluate_path("tools/package/app.tar.gz")
        self.assertEqual(dec, ExcludeDecision.ALLOW)

        dec, rule_id, _ = self.engine.evaluate_path("tools/package/rootfs/lib/libasan_preinit.o")
        self.assertEqual(dec, ExcludeDecision.ALLOW)

    def test_unapproved_archives_and_keys_blocked(self):
        dec, rule_id, _ = self.engine.evaluate_path("component/suspicious.zip")
        self.assertEqual(dec, ExcludeDecision.BLOCK_REVIEW)

        dec, rule_id, _ = self.engine.evaluate_path("component/server.pem")
        self.assertEqual(dec, ExcludeDecision.BLOCK_REVIEW)

    def test_content_scanner_ip_and_email(self):
        # 1. Private internal IP in core code -> Block
        bad_code = b"int connect() { return connect_to(\"10.42.0.252\"); }\n"
        passed, name, hint = self.engine.scan_content_blob("app/mickey_smart/src/net.c", bad_code)
        self.assertFalse(passed)
        self.assertEqual(name, "internal_ip_leak")

        # 2. Private developer email in core code -> Block
        bad_email = b"// Author: developer@gmail.com\n"
        passed, name, hint = self.engine.scan_content_blob("app/mickey_smart/src/net.c", bad_email)
        self.assertFalse(passed)
        self.assertEqual(name, "personal_email_leak")

        # 3. Third-party copyright header -> Exempted
        copyright_header = b"/* Copyright (C) 2012 author@gmail.com */\n"
        passed, name, hint = self.engine.scan_content_blob("include/libavutil/audio_fifo.h", copyright_header)
        self.assertTrue(passed)

if __name__ == "__main__":
    unittest.main()
