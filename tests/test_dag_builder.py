import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from engine.git_adapter import GitAdapter
from engine.dag_builder import DAGBuilder, DAGEngineError

class TestDAGBuilder(unittest.TestCase):
    def setUp(self):
        source_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../smart"))
        target_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../smart_encrypted"))
        self.source_git = GitAdapter(source_dir)
        self.target_git = GitAdapter(target_dir)

    def test_boundary_calculation_and_closure(self):
        # Base commit in Repo A
        base_a = "3962aed93e61d3d08e8d1f60c154575f19ee94da"
        tip_a = self.source_git.rev_parse("refs/heads/main")

        # 1. Test failure when parent f0b7c674 is missing
        broken_map = {base_a: "5f0f16ab0dbe985a12f135f6bbda0b47d8c83bcc"}
        dag_broken = DAGBuilder(self.source_git, self.target_git, broken_map)
        with self.assertRaises(DAGEngineError) as ctx:
            dag_broken.compute_sync_plan(tip_a, base_a)
        self.assertIn("External parent boundary check failed", str(ctx.exception))

        # 2. Test success when both external boundary parents are present
        complete_map = {
            base_a: "5f0f16ab0dbe985a12f135f6bbda0b47d8c83bcc",
            "f0b7c674931b1ffaaa85c9b041717c488e09b097": "653f8511670582c09c7b5cf498c67b35602be32e"
        }
        dag_ok = DAGBuilder(self.source_git, self.target_git, complete_map)
        commits_in_s, boundary_b = dag_ok.compute_sync_plan(tip_a, base_a)

        self.assertEqual(len(commits_in_s), 56)
        self.assertEqual(len(boundary_b), 2)
        self.assertIn(base_a, boundary_b)
        self.assertIn("f0b7c674931b1ffaaa85c9b041717c488e09b097", boundary_b)

if __name__ == "__main__":
    unittest.main()
