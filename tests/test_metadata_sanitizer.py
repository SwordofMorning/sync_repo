import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine.config_loader import SyncConfig
from engine.metadata_sanitizer import MetadataSanitizer, SanitizerError

class TestMetadataSanitizer(unittest.TestCase):
    def setUp(self):
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.config = SyncConfig(base_dir)
        repo_smart = self.config.get_repo("smart")
        self.sanitizer = MetadataSanitizer(
            self.config.global_settings.get("identity_map", {}),
            repo_smart.get("message_sanitization_rules", [])
        )

    def test_identity_mapping(self):
        name, email = self.sanitizer.sanitize_identity("gwp", "gwp.workspace@gmail.com")
        self.assertEqual(name, "龚文平")
        self.assertEqual(email, "wenping.gong@vitalchem.com")

        name, email = self.sanitizer.sanitize_identity("fzy", "fzy@11.com")
        self.assertEqual(name, "樊振宇")
        self.assertEqual(email, "zhenyu.fan@vitalchem.com")

    def test_unknown_author_fails_closed(self):
        with self.assertRaises(SanitizerError):
            self.sanitizer.sanitize_identity("stranger", "hacker@evil.com")

    def test_cherry_pick_removal(self):
        raw = "fix issue\n\n(cherry picked from commit 1ef2d26034567890123456789012345678901234)\n"
        clean = self.sanitizer.sanitize_message(raw)
        self.assertNotIn("cherry picked", clean)
        self.assertNotIn("1ef2d260", clean)
        self.assertEqual(clean.strip(), "fix issue")

    def test_merge_message_sanitization(self):
        # 1. Merge remote-tracking branch into private branch
        raw1 = "Merge remote-tracking branch 'origin/main' into ui-layout"
        clean1 = self.sanitizer.sanitize_message(raw1)
        self.assertEqual(clean1.strip(), "Merge branch 'main'")
        self.assertNotIn("$1", clean1)

        # 2. Merge hash with private branch
        raw2 = "Merge 63af6925 (origin/auto_shutter_fix): ntp sync"
        clean2 = self.sanitizer.sanitize_message(raw2)
        self.assertTrue(clean2.startswith("Merge branch 'auto_shutter_fix'"))
        self.assertNotIn("63af6925", clean2)
        self.assertNotIn("$1", clean2)

if __name__ == "__main__":
    unittest.main()
