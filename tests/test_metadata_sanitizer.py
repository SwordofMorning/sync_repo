import os
import sys
import unittest

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

    @staticmethod
    def _commit_metadata():
        return {
            "author_name": "gwp",
            "author_email": "gwp.workspace@gmail.com",
            "author_date": "2025-01-02T03:04:05+08:00",
            "committer_name": "fzy",
            "committer_email": "fzy@11.com",
            "committer_date": "2025-01-03T04:05:06+08:00",
            "message": "fix issue\n",
        }

    def test_identity_mapping(self):
        name, email = self.sanitizer.sanitize_identity("gwp", "gwp.workspace@gmail.com")
        self.assertEqual(name, "龚文平")
        self.assertEqual(email, "wenping.gong@vitalchem.com")

        name, email = self.sanitizer.sanitize_identity("fzy", "fzy@11.com")
        self.assertEqual(name, "樊振宇")
        self.assertEqual(email, "zhenyu.fan@vitalchem.com")

    def test_identity_whitespace_is_stripped(self):
        self.assertEqual(
            self.sanitizer.sanitize_identity(" gwp \t", " gwp.workspace@gmail.com "),
            ("龚文平", "wenping.gong@vitalchem.com"),
        )

    def test_canonical_values_are_idempotent_at_17(self):
        for source in self.sanitizer.identity_map:
            name, email = source.rsplit(" <", 1)
            canonical = self.sanitizer.sanitize_identity(name, email[:-1])
            with self.subTest(source=source):
                self.assertEqual(self.sanitizer.sanitize_identity(*canonical), canonical)
                self.assertEqual(
                    self.sanitizer.sanitize_identity(" " + canonical[0], canonical[1] + " "),
                    canonical,
                )

    def test_approved_external_identity_is_exact_allowlist(self):
        identity_map = {"private <private@example.org>": "Employee <employee@vitalchem.com>"}
        sanitizer = MetadataSanitizer(identity_map, [], ["Partner <partner@example.org>"])
        self.assertIs(sanitizer.identity_map, identity_map)
        self.assertEqual(
            sanitizer.approved_canonical_identities,
            {"Employee <employee@vitalchem.com>", "Partner <partner@example.org>"},
        )
        self.assertEqual(
            sanitizer.sanitize_identity(" Partner ", " partner@example.org "),
            ("Partner", "partner@example.org"),
        )
        for name, email in [("Impostor", "partner@example.org"), ("Partner", "other@example.org")]:
            with self.subTest(name=name, email=email), self.assertRaises(SanitizerError):
                sanitizer.sanitize_identity(name, email)
        with self.assertRaises(SanitizerError):
            MetadataSanitizer(identity_map, []).sanitize_identity("Partner", "partner@example.org")

    def test_unapproved_corporate_identities_fail_closed_at_17(self):
        identities = [
            ("stranger", "stranger@vitalchem.com"),
            ("stranger", "wenping.gong@vitalchem.com"),
            ("龚文平", "unapproved@vitalchem.com"),
            ("龚文平", "wenping.gong@vitalchem.com.evil.org"),
        ]
        for name, email in identities:
            with self.subTest(name=name, email=email), self.assertRaises(SanitizerError):
                self.sanitizer.sanitize_identity(name, email)

    def test_unknown_author_fails_closed(self):
        with self.assertRaises(SanitizerError):
            self.sanitizer.sanitize_identity("stranger", "hacker@evil.com")

    def test_malformed_mapped_identities_fail_closed(self):
        for mapped in ["Employee", " <employee@example.org>", "Employee < >", "Bad\nName <a@b.org>"]:
            with self.subTest(mapped=mapped), self.assertRaises(SanitizerError):
                MetadataSanitizer({"private <private@example.org>": mapped}, []).sanitize_identity(
                    "private", "private@example.org"
                )

    def test_build_commit_env_maps_both_identities_and_preserves_dates(self):
        meta = self._commit_metadata()
        env, message = self.sanitizer.build_commit_env(meta)
        self.assertEqual(env, {
            "GIT_AUTHOR_NAME": "龚文平",
            "GIT_AUTHOR_EMAIL": "wenping.gong@vitalchem.com",
            "GIT_AUTHOR_DATE": meta["author_date"],
            "GIT_COMMITTER_NAME": "樊振宇",
            "GIT_COMMITTER_EMAIL": "zhenyu.fan@vitalchem.com",
            "GIT_COMMITTER_DATE": meta["committer_date"],
        })
        self.assertEqual(message, "fix issue\n")

    def test_build_commit_env_rejects_unknown_author_and_committer_in_both_directions(self):
        for direction in ["A2B", "B2A"]:
            for role in ["author", "committer"]:
                meta = self._commit_metadata()
                meta[role + "_name"] = "Unapproved"
                meta[role + "_email"] = "unapproved@vitalchem.com"
                with self.subTest(direction=direction, role=role), self.assertRaises(SanitizerError):
                    self.sanitizer.build_commit_env(meta, direction=direction)

    def test_build_commit_env_accepts_canonical_identities_in_both_directions(self):
        meta = self._commit_metadata()
        for role in ["author", "committer"]:
            meta[role + "_name"], meta[role + "_email"] = self.sanitizer.sanitize_identity(
                meta[role + "_name"], meta[role + "_email"]
            )
        env_a, message_a = self.sanitizer.build_commit_env(meta, direction="A2B")
        env_b, message_b = self.sanitizer.build_commit_env(meta, direction="B2A")
        self.assertEqual(env_a, env_b)
        self.assertEqual(message_a, message_b)

    def test_build_commit_env_accepts_approved_external_author_and_committer(self):
        sanitizer = MetadataSanitizer({}, [], ["Partner <partner@example.org>"])
        meta = self._commit_metadata()
        for role in ["author", "committer"]:
            meta[role + "_name"] = "Partner"
            meta[role + "_email"] = "partner@example.org"
        env, _ = sanitizer.build_commit_env(meta, direction="B2A")
        self.assertEqual(env["GIT_AUTHOR_EMAIL"], "partner@example.org")
        self.assertEqual(env["GIT_COMMITTER_EMAIL"], "partner@example.org")

    def test_cherry_pick_removal(self):
        raw = "fix issue\n\n(cherry picked from commit 1ef2d26034567890123456789012345678901234)\n"
        clean = self.sanitizer.sanitize_message(raw)
        self.assertNotIn("cherry picked", clean)
        self.assertNotIn("1ef2d260", clean)
        self.assertEqual(clean.strip(), "fix issue")

    def test_merge_message_sanitization(self):
        raw1 = "Merge remote-tracking branch 'origin/main' into ui-layout"
        clean1 = self.sanitizer.sanitize_message(raw1)
        self.assertEqual(clean1.strip(), "Merge branch 'main'")
        self.assertNotIn("$1", clean1)

        raw2 = "Merge 63af6925 (origin/auto_shutter_fix): ntp sync"
        clean2 = self.sanitizer.sanitize_message(raw2)
        self.assertTrue(clean2.startswith("Merge branch 'auto_shutter_fix'"))
        self.assertNotIn("63af6925", clean2)
        self.assertNotIn("$1", clean2)


if __name__ == "__main__":
    unittest.main()
