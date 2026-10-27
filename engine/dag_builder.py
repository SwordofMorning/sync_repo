from typing import List, Dict, Set, Tuple
from engine.git_adapter import GitAdapter, GitError

class DAGEngineError(Exception):
    pass

class DAGBuilder:
    def __init__(self, source_git: GitAdapter, target_git: GitAdapter, commit_map: Dict[str, str]):
        self.source_git = source_git
        self.target_git = target_git
        self.commit_map = commit_map  # source_commit -> target_commit

    def compute_sync_plan(self, source_tip: str, last_published_a: str) -> Tuple[List[str], Set[str]]:
        """
        Calculates S = Ancestors(source_tip) - Ancestors(last_published_a)
        and external parent boundary B = union(parents(c) for c in S) - S.
        Returns: (ordered_commits_in_S, external_boundary_B)
        """
        # 1. Verify source_tip and last_published_a exist in source repo
        try:
            full_source_tip = self.source_git.rev_parse(source_tip)
        except GitError as e:
            raise DAGEngineError(f"Cannot resolve source tip '{source_tip}': {e}")

        try:
            full_last_pub_a = self.source_git.rev_parse(last_published_a)
        except GitError as e:
            raise DAGEngineError(f"Cannot resolve last published A commit '{last_published_a}': {e}")

        # 2. Verify last_published_a is ancestor of source_tip
        if not self.source_git.merge_base_is_ancestor(full_last_pub_a, full_source_tip):
            raise DAGEngineError(
                f"Source history diverged: '{full_last_pub_a}' is not an ancestor of source tip '{full_source_tip}'"
            )

        # 3. Extract sequence S in topological order (oldest to newest)
        commits_in_s = self.source_git.rev_list_topo(full_last_pub_a, full_source_tip)
        set_s = set(commits_in_s)

        # 4. Compute external parent boundary B
        boundary_b = set()
        for c in commits_in_s:
            parents = self.source_git.get_commit_parents(c)
            for p in parents:
                if p not in set_s:
                    boundary_b.add(p)

        # 5. Pre-check: All commits in boundary B must have a verified mapping in commit_map
        missing_parents = []
        for p in boundary_b:
            if p not in self.commit_map:
                missing_parents.append(p)

        if missing_parents:
            raise DAGEngineError(
                f"External parent boundary check failed! Missing mapping for parent commit(s): {missing_parents}. "
                f"Replay cannot proceed without valid boundary parents."
            )

        return commits_in_s, boundary_b
