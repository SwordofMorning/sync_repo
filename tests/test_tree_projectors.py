import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine.content_normalizer import ContentNormalizer, TSD_MAGIC_HEADER
from engine.exclude_engine import ExcludeDecision, ExcludeEngine
from engine.git_adapter import GitAdapter, GitError
from engine.path_validator import NamespaceCollisionError
from engine.reverse_tree_projector import ReverseProjectionError, ReverseTreeProjector
from engine.tree_projector import SecurityBlockError, TreeProjectionError, TreeProjector


class ProjectorGitFixture(unittest.TestCase):
    COMMIT_ENV = {
        "GIT_AUTHOR_NAME": "Projection Test",
        "GIT_AUTHOR_EMAIL": "projection@example.org",
        "GIT_COMMITTER_NAME": "Projection Test",
        "GIT_COMMITTER_EMAIL": "projection@example.org",
        "GIT_AUTHOR_DATE": "2025-01-01T00:00:00+00:00",
        "GIT_COMMITTER_DATE": "2025-01-01T00:00:00+00:00",
    }

    def setUp(self):
        playground = os.path.abspath(os.path.join(
            os.path.dirname(__file__), "../../../.playground/sync/tmp_tree_projector_tests"
        ))
        os.makedirs(playground, exist_ok=True)
        self.sandbox = tempfile.TemporaryDirectory(dir=playground)
        self.addCleanup(self.sandbox.cleanup)
        self.root = self.sandbox.name
        self.git_a, self.git_b = self.repo("a"), self.repo("b")
        configs = os.path.join(os.path.dirname(__file__), "../configs")
        with open(os.path.join(configs, "manifest_smart.json"), encoding="utf-8") as handle:
            manifest = json.load(handle)
        # The production manifest names other scripts; this fixture explicitly
        # authorizes build.sh to exercise the requested LF-required root script.
        manifest["root_files_allowlist"].append("build.sh")
        with open(os.path.join(configs, "exclude_rules.json"), encoding="utf-8") as handle:
            rules = json.load(handle)
        self.policy = ExcludeEngine(manifest, rules)

    def repo(self, name):
        path = os.path.join(self.root, name)
        os.makedirs(path)
        subprocess.run(
            ["git", "init", "-q", path], check=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        git = GitAdapter(path)
        git._run_checked(["config", "core.protectNTFS", "false"])
        git._run_checked(["symbolic-ref", "HEAD", "refs/heads/main"])
        with open(os.path.join(path, "untracked-sentinel"), "wb") as handle:
            handle.write(b"do not touch\n")
        return git

    def tree(self, git, files):
        nested = {}
        for path, value in files.items():
            mode, data = value if isinstance(value, tuple) else ("100644", value)
            cur = nested
            parts = path.split("/")
            for part in parts[:-1]:
                cur = cur.setdefault(part, {})
            self.assertNotIn(parts[-1], cur, "Fixture must not overwrite a directory")
            cur[parts[-1]] = (mode, "blob", git.hash_object_write(data))

        def build(node):
            records = []
            for name, value in node.items():
                if isinstance(value, dict):
                    records.append(("040000", "tree", build(value), name))
                else:
                    records.append((*value, name))
            return git.mktree_z(records)

        return build(nested)

    def commit(self, git, files, parents=(), message="fixture"):
        tree = self.tree(git, files)
        commit = git.commit_tree(tree, list(parents), message, env=self.COMMIT_ENV)
        git.update_ref("refs/heads/main", commit)
        git.read_tree(tree)
        return commit, tree

    @staticmethod
    def entries(git, tree, env=None):
        return {
            entry["path"]: (entry["mode"], entry["type"], entry["oid"])
            for entry in git.ls_tree_r_z_strict(tree, env=env)
        }

    @staticmethod
    def object_oids(git):
        return set(git._run_checked([
            "cat-file", "--batch-all-objects", "--batch-check=%(objectname)"
        ]).splitlines())

    @staticmethod
    def state(git):
        refs = git._run_checked(["for-each-ref", "--format=%(refname) %(objectname)"])
        index_path = os.path.join(git.repo_dir, ".git", "index")
        index = None
        if os.path.exists(index_path):
            with open(index_path, "rb") as handle:
                index = handle.read()
        files = {}
        for base, dirs, names in os.walk(git.repo_dir):
            dirs[:] = [name for name in dirs if name != ".git"]
            for name in names:
                full = os.path.join(base, name)
                with open(full, "rb") as handle:
                    files[os.path.relpath(full, git.repo_dir)] = handle.read()
        return refs, index, files

    def anchor(self, files_a):
        parent_a, tree_a = self.commit(self.git_a, files_a, message="A anchor")
        tree_b = TreeProjector(self.git_a, self.git_b, self.policy).project_commit_tree(parent_a)
        parent_b = self.git_b.commit_tree(tree_b, [], "B anchor", env=self.COMMIT_ENV)
        self.git_b.update_ref("refs/heads/main", parent_b)
        self.git_b.read_tree(tree_b)
        shared_b = {
            path: (mode, self.git_b.cat_file_blob(oid))
            for path, (mode, _, oid) in self.entries(self.git_b, tree_b).items()
        }
        return parent_a, parent_b, tree_a, shared_b

    def isolated_env(self, git, name):
        objects = os.path.join(self.root, name)
        os.makedirs(objects)
        return {
            "GIT_OBJECT_DIRECTORY": objects,
            "GIT_ALTERNATE_OBJECT_DIRECTORIES": os.path.join(git.repo_dir, ".git", "objects"),
        }


class TestForwardTreeProjector(ProjectorGitFixture):
    def test_legacy_three_argument_api_and_typed_forward_normalization(self):
        files = {
            "Makefile": b"all:\r\r\n\techo ok\r\n",
            "build.sh": ("100755", b"#!/bin/sh\r\necho ok\r\r\n"),
            "component/main.c": b"int main(void) { return 0; }\r\n",
            "component/firmware.bin": b"\x00A\r\nB",
            "tools/package/app.tar.gz": b"\x00approved archive\r\n",
        }
        commit, tree_a = self.commit(self.git_a, files)
        projector = TreeProjector(self.git_a, self.git_b, self.policy)
        self.assertEqual(projector.policy_digest, "default")
        self.assertTrue(issubclass(SecurityBlockError, TreeProjectionError))
        tree_b = projector.project_commit_tree(commit)
        entries = self.entries(self.git_b, tree_b)
        self.assertEqual(self.git_b.cat_file_blob(entries["Makefile"][2]), b"all:\n\techo ok\n")
        self.assertEqual(self.git_b.cat_file_blob(entries["build.sh"][2]), b"#!/bin/sh\necho ok\n")
        self.assertEqual(entries["build.sh"][0], "100755")
        for path in ("component/main.c", "component/firmware.bin", "tools/package/app.tar.gz"):
            self.assertEqual(entries[path], self.entries(self.git_a, tree_a)[path])
        self.assertEqual(tree_b, projector.project_commit_tree(commit))

    def test_at_02_historical_private_blob_never_enters_target_store(self):
        base_files = {
            "Makefile": b"all:\n\techo old\n",
            "component/main.c": b"int public_value = 1;\n",
            "component/secret.docx": b"PK\x03\x04historical-private-document",
        }
        base, tree_base = self.commit(self.git_a, base_files)
        projector = TreeProjector(self.git_a, self.git_b, self.policy, "policy-one")
        projector.project_commit_tree(base)
        tip_files = dict(base_files, Makefile=b"all:\n\techo new\n")
        tip, tree_tip = self.commit(self.git_a, tip_files, [base])
        self.assertEqual(
            self.entries(self.git_a, tree_base)["component/secret.docx"],
            self.entries(self.git_a, tree_tip)["component/secret.docx"],
        )
        before_precheck = self.object_oids(self.git_b)
        projector.stream_approved_objects(base, tip)
        self.assertEqual(before_precheck, self.object_oids(self.git_b))
        tree_b = projector.project_commit_tree(tip)
        self.assertNotIn("component/secret.docx", self.entries(self.git_b, tree_b))
        secret_oid = self.entries(self.git_a, tree_tip)["component/secret.docx"][2]
        component_oid = next(e["oid"] for e in self.git_a.ls_tree_z(tree_tip) if e["name"] == "component")
        for oid in (secret_oid, component_oid, tree_tip, tip):
            self.assertFalse(self.git_b.has_object(oid), f"Unapproved closure object imported: {oid}")

    def test_at_03_path_and_content_blocks_precede_every_target_write(self):
        cases = [
            ("component/server.pem", b"private credential", "BLOCK_SUSPECTED_CREDENTIALS"),
            ("component/network.c", b'const char *host = "10.42.0.99";\n', "internal_ip_leak"),
            ("component/network.c", b"// INTERNAL_ONLY\n", "confidential_marker"),
        ]
        for index, (path, data, rule) in enumerate(cases):
            with self.subTest(path=path, rule=rule):
                commit, _ = self.commit(self.git_a, {"Makefile": b"all:\n\techo ok\n", path: data})
                target = self.repo(f"blocked-target-{index}")
                projector = TreeProjector(self.git_a, target, self.policy)
                before = self.object_oids(target), self.state(target)
                with patch.object(target, "hash_object_write", wraps=target.hash_object_write) as write, \
                     patch.object(target, "mktree_z", wraps=target.mktree_z) as mktree:
                    with self.assertRaises(SecurityBlockError):
                        projector.project_commit_tree(commit)
                    write.assert_not_called()
                    mktree.assert_not_called()
                self.assertEqual(before, (self.object_oids(target), self.state(target)))
                self.assertTrue(any(
                    record["path"] == path and record["rule_id"] == rule
                    and record["decision"] == ExcludeDecision.BLOCK_REVIEW
                    for record in self.policy.audit_records
                ))

    def test_range_precheck_rejects_leak_removed_at_tip_without_importing(self):
        base, _ = self.commit(self.git_a, {"Makefile": b"all:\n"})
        leaking, _ = self.commit(self.git_a, {
            "Makefile": b"all:\n", "component/leak.c": b"// INTERNAL_ONLY\n"
        }, [base])
        tip, _ = self.commit(self.git_a, {"Makefile": b"all:\n"}, [leaking])
        projector = TreeProjector(self.git_a, self.git_b, self.policy)
        with self.assertRaises(SecurityBlockError):
            projector.stream_approved_objects(base, tip)
        self.assertEqual(self.object_oids(self.git_b), set())
        self.assertFalse(projector.objects_streamed)

    def test_at2_01_ls_tree_failure_is_not_cached_as_empty_subtree(self):
        commit, root = self.commit(self.git_a, {"component/main.c": b"int value = 1;\n"})
        subtree = self.git_a.ls_tree_z(root)[0]["oid"]
        projector = TreeProjector(self.git_a, self.git_b, self.policy)
        original_run = self.git_a._run

        def fail_ls_tree(args, stdin_bytes=None, env=None):
            if args == ["ls-tree", "-z", subtree]:
                return b"", b"fatal: corrupt tree", 128
            return original_run(args, stdin_bytes=stdin_bytes, env=env)

        with patch.object(self.git_a, "_run", side_effect=fail_ls_tree):
            with self.assertRaisesRegex(GitError, "exit=128"):
                projector.project_commit_tree(commit)
        self.assertNotIn(("component", subtree, "default"), projector._subtree_cache)
        self.assertNotIn(("component", subtree, "default"), projector._preflight_cache)
        self.assertEqual(self.object_oids(self.git_b), set())
        repaired = projector.project_commit_tree(commit)
        self.assertIn("component/main.c", self.entries(self.git_b, repaired))
        # A failure during the second (projection) pass must not poison its cache either.
        retry = TreeProjector(self.git_a, self.git_b, self.policy)
        retry._preflight_subtree(commit, "", root)
        with patch.object(self.git_a, "_run", side_effect=fail_ls_tree):
            with self.assertRaises(GitError):
                retry.project_commit_tree(commit)
        self.assertNotIn(("component", subtree, "default"), retry._subtree_cache)

    def test_strict_utf8_failure_never_imports_or_caches_root(self):
        blob = self.git_a.hash_object_write(b"invalid-path-content")
        records = f"100644 blob {blob}\t".encode("ascii") + b"bad_\xff.c\0"
        tree = self.git_a._run_checked(["mktree", "-z"], stdin_bytes=records).decode("ascii").strip()
        commit = self.git_a.commit_tree(tree, [], "bad UTF-8", env=self.COMMIT_ENV)
        projector = TreeProjector(self.git_a, self.git_b, self.policy)
        with self.assertRaisesRegex(GitError, "UTF-8"):
            projector.project_commit_tree(commit)
        self.assertEqual(projector._subtree_cache, {})
        self.assertEqual(self.object_oids(self.git_b), set())

    def test_at2_02_ancestor_prune_and_shared_mode_platform_blocks(self):
        commit, _ = self.commit(self.git_a, {
            "docs/pkg.docx/readme.md": b"private because of ancestor",
            "component/main.c": b"int ok;\n",
        })
        tree_b = TreeProjector(self.git_a, self.git_b, self.policy).project_commit_tree(commit)
        self.assertEqual(set(self.entries(self.git_b, tree_b)), {"component/main.c"})
        bad_entries = [
            ("docs/secret.pem/a.c", b"blocked by ancestor"),
            ("tools/a:b.c", b"invalid path"),
            ("component/link.c", ("120000", b"main.c")),
        ]
        for index, (path, value) in enumerate(bad_entries):
            with self.subTest(path=path):
                bad, _ = self.commit(self.git_a, {path: value})
                target = self.repo(f"bad-mode-{index}")
                with self.assertRaises(SecurityBlockError):
                    TreeProjector(self.git_a, target, self.policy).project_commit_tree(bad)
                self.assertEqual(self.object_oids(target), set())

    def test_casefolded_forward_namespace_collision_precedes_import(self):
        commit, _ = self.commit(self.git_a, {
            "docs/pkg.c": b"int lower;\n", "docs/PKG.C/new.c": b"int upper;\n"
        })
        with self.assertRaises(SecurityBlockError) as raised:
            TreeProjector(self.git_a, self.git_b, self.policy).project_commit_tree(commit)
        self.assertIsInstance(raised.exception.__cause__, NamespaceCollisionError)
        self.assertEqual(self.object_oids(self.git_b), set())

    def test_subtree_cache_is_bound_to_path_and_policy_digest(self):
        data = b"int shared;\n"
        commit, root = self.commit(self.git_a, {
            "docs/pkg.docx/same.c": data, "component/public/same.c": data,
        })
        projector = TreeProjector(self.git_a, self.git_b, self.policy, "epoch-one")
        first = projector.project_commit_tree(commit)
        self.assertEqual(set(self.entries(self.git_b, first)), {"component/public/same.c"})
        self.assertIn(("", root, "epoch-one"), projector._subtree_cache)
        self.policy.rules.insert(0, {
            "rule_id": "NEW_PRUNE", "category": "FILENAME", "pattern": "same.c", "action": "PRUNE"
        })
        projector.policy_digest = "epoch-two"
        second = projector.project_commit_tree(commit)
        self.assertEqual(self.entries(self.git_b, second), {})
        self.assertIn(("", root, "epoch-two"), projector._subtree_cache)

    def test_target_object_env_does_not_hide_source_or_write_production(self):
        commit, _ = self.commit(self.git_a, {"build.sh": ("100755", b"echo isolated\r\n")})
        env = self.isolated_env(self.git_b, "objects-b")
        before = self.state(self.git_a), self.state(self.git_b)
        tree = TreeProjector(self.git_a, self.git_b, self.policy, target_env=env).project_commit_tree(commit)
        self.assertFalse(self.git_b.has_object(tree))
        entries = self.entries(self.git_b, tree, env=env)
        self.assertEqual(self.git_b.cat_file_blob(entries["build.sh"][2], env=env), b"echo isolated\n")
        self.assertEqual(self.object_oids(self.git_b), set())
        self.assertEqual(before, (self.state(self.git_a), self.state(self.git_b)))


class TestReverseTreeProjector(ProjectorGitFixture):
    def test_at_01_directory_replaced_by_file_cannot_destroy_private_descendant(self):
        parent_a, parent_b, tree_a, files_b = self.anchor({
            "docs/pkg/private.docx": b"PK private document",
            "docs/pkg/readme.md": b"public readme\n",
        })
        files_b.pop("docs/pkg/readme.md")
        files_b["docs/pkg"] = b"replace directory by file\n"
        commit_b, _ = self.commit(self.git_b, files_b, [parent_b])
        reverse = ReverseTreeProjector(self.git_a, self.git_b, self.policy)
        private_before = reverse.compute_private_complement(tree_a)
        self.assertIn("docs/pkg", private_before[1])
        before = self.state(self.git_a), self.object_oids(self.git_a)
        with patch.object(reverse, "_build_tree_strict", wraps=reverse._build_tree_strict) as build, \
             patch.object(self.git_a, "hash_object_write", wraps=self.git_a.hash_object_write) as write:
            with self.assertRaisesRegex(ReverseProjectionError, "private asset"):
                reverse.project_reverse_commit_tree(parent_a, parent_b, commit_b)
            build.assert_not_called()
            write.assert_not_called()
        self.assertEqual(before, (self.state(self.git_a), self.object_oids(self.git_a)))
        self.assertEqual(private_before, reverse.compute_private_complement(tree_a))

    def test_at2_02_reverse_rejects_private_ancestor_in_b_full_tree(self):
        parent_a, parent_b, _, files_b = self.anchor({
            "docs/pkg.docx": b"private office document", "component/main.c": b"int ok;\n"
        })
        files_b["docs/PKG.DOCX/new.c"] = b"int new_value;\n"
        commit_b, _ = self.commit(self.git_b, files_b, [parent_b])
        reverse = ReverseTreeProjector(self.git_a, self.git_b, self.policy)
        before = self.state(self.git_a), self.object_oids(self.git_a)
        with self.assertRaises(ReverseProjectionError):
            reverse.project_reverse_commit_tree(parent_a, parent_b, commit_b)
        self.assertEqual(before, (self.state(self.git_a), self.object_oids(self.git_a)))

    def test_at2_03_private_shared_casefold_prefix_collision_uses_trie(self):
        parent_a, parent_b, _, files_b = self.anchor({
            "docs/pkg.docx": b"private office document", "component/main.c": b"int ok;\n"
        })
        # An exact approved exception permits the B leaf despite its pruned
        # directory suffix. The cross-origin trie must STILL protect A's leaf.
        self.policy.dependency_exceptions["docs/PKG.DOCX/new.c"] = {"reason": "test exact exception"}
        files_b["docs/PKG.DOCX/new.c"] = b"int new_value;\n"
        commit_b, _ = self.commit(self.git_b, files_b, [parent_b])
        reverse = ReverseTreeProjector(self.git_a, self.git_b, self.policy)
        before = self.state(self.git_a), self.object_oids(self.git_a)
        with patch.object(reverse, "_build_tree_strict", wraps=reverse._build_tree_strict) as build:
            with self.assertRaisesRegex(ReverseProjectionError, "namespace collision") as raised:
                reverse.project_reverse_commit_tree(parent_a, parent_b, commit_b)
            self.assertIsInstance(raised.exception.__cause__, NamespaceCollisionError)
            self.assertIn("pkg.docx", str(raised.exception))
            build.assert_not_called()
        self.assertEqual(before, (self.state(self.git_a), self.object_oids(self.git_a)))

    def test_clean_reverse_preserves_twenty_private_projects_and_normalizes_scripts(self):
        projects = [
            "DOT", "victory", "stc", "night_eye", "coti", "md_ir", "goblin", "lk_mini",
            "gk7205v300_mini", "snow_wol", "gunsight_kits", "TUBE_Q50L",
            "smart_customize2603", "test", "private_14", "private_15", "private_16",
            "private_17", "private_18", "private_19",
        ]
        files_a = {
            f"app/{name}/main.c": f"private-project-{index}\r\n".encode("ascii")
            for index, name in enumerate(projects)
        }
        files_a.update({
            "app/mickey_smart/main.c": b"int value = 1;\n",
            "app/Makefile": b"all:\n",
            "gwp_debug/state.c": b"INTERNAL_ONLY private debugging\r\n",
            "docs/private.docx": b"PK\x03\x04\x00private office bytes\r\n",
            "build.sh": ("100755", b"#!/bin/sh\necho old\n"),
        })
        parent_a, parent_b, tree_a, files_b = self.anchor(files_a)
        reverse = ReverseTreeProjector(self.git_a, self.git_b, self.policy)
        p_priv, a_priv = reverse.compute_private_complement(tree_a)
        self.assertEqual(len(projects), 20)
        self.assertEqual(len(p_priv), 22)
        files_b["app/mickey_smart/main.c"] = b"int value = 2;\r\n"
        files_b["build.sh"] = ("100755", b"#!/bin/sh\r\necho new\r\r\n")
        commit_b, tree_b = self.commit(self.git_b, files_b, [parent_b])
        before = self.state(self.git_a), self.state(self.git_b)
        new_tree, staged = reverse.project_reverse_commit_tree(parent_a, parent_b, commit_b)
        self.assertEqual(staged, {
            "app/mickey_smart/main.c": b"int value = 2;\n",
            "build.sh": b"#!/bin/sh\necho new\n",
        })
        self.assertEqual((p_priv, a_priv), reverse.compute_private_complement(new_tree))
        entries_after = self.entries(self.git_a, new_tree)
        self.assertTrue(all(entries_after[path] == triple for path, triple in p_priv.items()))
        for name in projects:
            old = self.git_a.rev_parse(f"{tree_a}:app/{name}")
            new = self.git_a.rev_parse(f"{new_tree}:app/{name}")
            self.assertEqual(old, new, f"Private project OID changed: app/{name}")
        self.assertEqual(entries_after["build.sh"][0], "100755")
        for path, canon in staged.items():
            self.assertEqual(self.git_a.cat_file_blob(entries_after[path][2]), canon)
        self.assertEqual(
            self.policy.compute_shared_norm(self.git_a, new_tree),
            self.policy.compute_shared_norm(self.git_b, tree_b),
        )
        self.assertEqual(before, (self.state(self.git_a), self.state(self.git_b)))

    def test_private_complement_uses_effective_ancestors_and_preserves_legacy_assets(self):
        parent_a, tree_a = self.commit(self.git_a, {
            "docs/pkg.docx/readme.md": b"private by ancestor",
            "gwp_debug/legacy:name.c": b"legacy private invalid Windows path",
            "app/DOT/link.c": ("120000", b"main.c"),
            "component/server.pem": b"historical blocked credential",
            "component/main.c": b"int ok;\n",
        })
        reverse = ReverseTreeProjector(self.git_a, self.git_b, self.policy)
        with patch.object(self.git_a, "ls_tree_r_z_strict", wraps=self.git_a.ls_tree_r_z_strict) as strict:
            private, ancestors = reverse.compute_private_complement(tree_a)
            strict.assert_called_once_with(tree_a, env=None)
        self.assertEqual(set(private), {
            "docs/pkg.docx/readme.md", "gwp_debug/legacy:name.c", "app/DOT/link.c",
            "component/server.pem",
        })
        self.assertEqual(ancestors, {"docs", "docs/pkg.docx", "gwp_debug", "app", "app/DOT", "component"})
        parent_b, _ = self.commit(self.git_b, {"component/main.c": b"int ok;\n"})
        commit_b, _ = self.commit(self.git_b, {"component/main.c": b"int ok;\n"}, [parent_b])
        new_tree, staged = reverse.project_reverse_commit_tree(parent_a, parent_b, commit_b)
        self.assertEqual((private, ancestors), reverse.compute_private_complement(new_tree))
        self.assertEqual(new_tree, tree_a)
        self.assertEqual(staged, {})

    def test_reverse_requires_exact_single_linear_parent(self):
        parent_a, parent_b, _, files_b = self.anchor({"component/main.c": b"int ok;\n"})
        side_parent, _ = self.commit(self.git_b, files_b, message="side root")
        no_parent, _ = self.commit(self.git_b, files_b, message="new root")
        wrong_parent, _ = self.commit(self.git_b, files_b, [side_parent], "wrong parent")
        merge, _ = self.commit(self.git_b, files_b, [parent_b, side_parent], "merge")
        reverse = ReverseTreeProjector(self.git_a, self.git_b, self.policy)
        before = self.object_oids(self.git_a), self.state(self.git_a)
        for commit in (no_parent, wrong_parent, merge):
            with self.subTest(commit=commit):
                with self.assertRaisesRegex(ReverseProjectionError, "NON_LINEAR_TOPOLOGY_HALT"):
                    reverse.project_reverse_commit_tree(parent_a, parent_b, commit)
        self.assertEqual(before, (self.object_oids(self.git_a), self.state(self.git_a)))

    def test_full_b_tree_validation_rejects_unchanged_historical_leaks(self):
        parent_a, _ = self.commit(self.git_a, {"component/main.c": b"int old;\n"})
        pollutants = [
            ("docs/private.docx", b"private office document"),
            ("component/old.c", b'const char *ip = "10.42.0.99";\n'),
            ("component/old.c", b"// INTERNAL_ONLY\n"),
            ("tools/opaque.bin", TSD_MAGIC_HEADER + b"undecryptable"),
        ]
        for path, value in pollutants:
            with self.subTest(path=path, value=value):
                files_b = {"component/main.c": b"int old;\n", path: value}
                parent_b, _ = self.commit(self.git_b, files_b)
                files_b["component/main.c"] = b"int new_value;\n"
                commit_b, _ = self.commit(self.git_b, files_b, [parent_b])
                before = self.object_oids(self.git_a), self.state(self.git_a)
                with self.assertRaises(ReverseProjectionError):
                    ReverseTreeProjector(self.git_a, self.git_b, self.policy).project_reverse_commit_tree(
                        parent_a, parent_b, commit_b
                    )
                self.assertEqual(before, (self.object_oids(self.git_a), self.state(self.git_a)))

    def test_reverse_decrypts_via_oid_bound_bridge_or_callable(self):
        plain = b"int value = 2;\r\n"
        raw = TSD_MAGIC_HEADER + b"fixture cipher payload"
        for bridge_kind in ("object", "callable"):
            with self.subTest(bridge=bridge_kind):
                parent_a, parent_b, _, files_b = self.anchor({"component/main.c": b"int value = 1;\n"})
                files_b["component/main.c"] = raw
                commit_b, tree_b = self.commit(self.git_b, files_b, [parent_b])
                oid = self.entries(self.git_b, tree_b)["component/main.c"][2]
                calls = []

                class Bridge:
                    def decrypt_blob_via_old_channel(self, data, *, expected_source_oid, hint_path):
                        calls.append((data, expected_source_oid, hint_path))
                        return plain

                def decrypt(data, path):
                    calls.append((data, oid, path))
                    return plain

                bridge = Bridge() if bridge_kind == "object" else decrypt
                tree_a, staged = ReverseTreeProjector(
                    self.git_a, self.git_b, self.policy, dlp_bridge=bridge
                ).project_reverse_commit_tree(parent_a, parent_b, commit_b)
                self.assertTrue(calls)
                self.assertTrue(all(call == (raw, oid, "component/main.c") for call in calls))
                self.assertEqual(staged, {"component/main.c": b"int value = 2;\n"})
                new_oid = self.entries(self.git_a, tree_a)["component/main.c"][2]
                self.assertEqual(self.git_a.cat_file_blob(new_oid), b"int value = 2;\n")

    def test_bridge_plaintext_leaks_or_residual_ciphertext_never_write_a(self):
        parent_a, parent_b, _, files_b = self.anchor({"component/main.c": b"int value = 1;\n"})
        raw = TSD_MAGIC_HEADER + b"encrypted source fixture"
        files_b["component/main.c"] = raw
        commit_b, _ = self.commit(self.git_b, files_b, [parent_b])
        for decrypted in (b"// INTERNAL_ONLY\n", b"// 10.42.0.99\n", raw):
            with self.subTest(decrypted=decrypted):
                before = self.object_oids(self.git_a), self.state(self.git_a)
                reverse = ReverseTreeProjector(
                    self.git_a, self.git_b, self.policy, dlp_bridge=lambda data, path: decrypted
                )
                with self.assertRaises(ReverseProjectionError):
                    reverse.project_reverse_commit_tree(parent_a, parent_b, commit_b)
                self.assertEqual(before, (self.object_oids(self.git_a), self.state(self.git_a)))

    def test_reverse_deletion_addition_mode_and_baseline_text_normalization(self):
        parent_a, parent_b, tree_a, files_b = self.anchor({
            "docs/private.docx": b"private doc",
            "component/general.c": b"int old;\r\n",
            "component/old.c": b"int obsolete;\n",
            "component/data.bin": b"\x00old\r\n",
        })
        files_b.pop("component/old.c")
        files_b["component/general.c"] = ("100755", b"int new_value;\n")
        files_b["component/new.c"] = b"int added;\r\n"
        files_b["component/data.bin"] = b"\x00new\r\n"
        commit_b, _ = self.commit(self.git_b, files_b, [parent_b])
        tree, staged = ReverseTreeProjector(self.git_a, self.git_b, self.policy).project_reverse_commit_tree(
            parent_a, parent_b, commit_b
        )
        self.assertEqual(staged, {
            "component/general.c": b"int new_value;\r\n",
            "component/new.c": b"int added;\n",
            "component/data.bin": b"\x00new\r\n",
        })
        entries = self.entries(self.git_a, tree)
        self.assertNotIn("component/old.c", entries)
        self.assertEqual(entries["component/general.c"][0], "100755")
        self.assertEqual(entries["docs/private.docx"], self.entries(self.git_a, tree_a)["docs/private.docx"])

    def test_strict_builder_refuses_file_directory_and_case_overwrites_without_writes(self):
        reverse = ReverseTreeProjector(self.git_a, self.git_b, self.policy)
        blob = self.git_a.hash_object_write(b"content")
        leaf = ("100644", "blob", blob)
        cases = [
            {"docs/pkg": leaf, "docs/pkg/new.c": leaf},
            {"docs/pkg/new.c": leaf, "docs/pkg": leaf},
            {"docs/pkg.docx": leaf, "docs/PKG.DOCX/new.c": leaf},
            {"docs/a/new.c": leaf, "docs/A/other.c": leaf},
        ]
        before = self.object_oids(self.git_a)
        for entries in cases:
            with self.subTest(paths=list(entries)):
                with self.assertRaises(ReverseProjectionError):
                    reverse._build_tree_strict(entries)
        self.assertEqual(before, self.object_oids(self.git_a))

    def test_shared_norm_gate_rejects_inconsistent_unchanged_anchor(self):
        parent_a, _ = self.commit(self.git_a, {"component/a.c": b"int only_in_a;\n"})
        parent_b, _ = self.commit(self.git_b, {"component/b.c": b"int only_in_b;\n"})
        commit_b, _ = self.commit(self.git_b, {"component/b.c": b"int only_in_b;\n"}, [parent_b])
        before = self.state(self.git_a)
        with self.assertRaisesRegex(ReverseProjectionError, "SharedNorm"):
            ReverseTreeProjector(self.git_a, self.git_b, self.policy).project_reverse_commit_tree(
                parent_a, parent_b, commit_b
            )
        self.assertEqual(before, self.state(self.git_a))

    def test_reverse_target_env_is_used_for_candidate_reads_and_writes(self):
        parent_a, parent_b, tree_a, files_b = self.anchor({
            "docs/private.docx": b"private doc", "build.sh": ("100755", b"echo old\n")
        })
        files_b["build.sh"] = ("100755", b"echo reverse-isolated\r\n")
        commit_b, _ = self.commit(self.git_b, files_b, [parent_b])
        env = self.isolated_env(self.git_a, "objects-a")
        before = self.object_oids(self.git_a), self.state(self.git_a), self.state(self.git_b)
        reverse = ReverseTreeProjector(self.git_a, self.git_b, self.policy, target_env_a=env)
        tree, staged = reverse.project_reverse_commit_tree(parent_a, parent_b, commit_b)
        self.assertFalse(self.git_a.has_object(tree))
        entries = self.entries(self.git_a, tree, env=env)
        self.assertEqual(self.git_a.cat_file_blob(entries["build.sh"][2], env=env), b"echo reverse-isolated\n")
        self.assertEqual(staged, {"build.sh": b"echo reverse-isolated\n"})
        self.assertEqual(reverse.compute_private_complement(tree), reverse.compute_private_complement(tree_a))
        self.assertEqual(before, (self.object_oids(self.git_a), self.state(self.git_a), self.state(self.git_b)))


if __name__ == "__main__":
    unittest.main()
