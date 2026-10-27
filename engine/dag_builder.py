from typing import Dict, List, Set, Tuple

from engine.git_adapter import GitAdapter, GitError


class DAGEngineError(Exception):
    pass


class NonLinearHistoryError(DAGEngineError):
    pass


class ConcurrentDivergenceError(DAGEngineError):
    pass


class HistoryRewrittenError(DAGEngineError):
    pass


def _validate_linear_chain(
    commits: List[str], parents_by_commit: Dict[str, List[str]], base: str, tip: str
) -> None:
    """Require the complete ordered interval to be a direct single-parent chain."""
    expected_parent = base
    for commit in commits:
        parents = parents_by_commit[commit]
        if parents != [expected_parent]:
            raise NonLinearHistoryError(
                f"S_NON_LINEAR_HALT: NON_LINEAR_TOPOLOGY_HALT: commit '{commit}' "
                f"must have exactly one parent '{expected_parent}', got {parents}"
            )
        expected_parent = commit
    if expected_parent != tip:
        raise NonLinearHistoryError(
            f"S_NON_LINEAR_HALT: NON_LINEAR_TOPOLOGY_HALT: interval from '{base}' "
            f"does not form a complete single-parent chain to '{tip}'"
        )


class DAGBuilder:
    def __init__(self, source_git: GitAdapter, target_git: GitAdapter, commit_map: Dict[str, str]):
        self.source_git = source_git
        self.target_git = target_git
        self.commit_map = commit_map  # source_commit -> target_commit

    def compute_sync_plan(
        self, source_tip: str, last_published_a: str, enforce_linear: bool = False
    ) -> Tuple[List[str], Set[str]]:
        """
        Calculates S = Ancestors(source_tip) - Ancestors(last_published_a)
        and external parent boundary B = union(parents(c) for c in S) - S.
        Returns: (ordered_commits_in_S, external_boundary_B).
        Phase 1 callers enable enforce_linear; legacy DAG callers may omit it.
        """
        try:
            full_source_tip = self.source_git.rev_parse(source_tip)
        except GitError as exc:
            raise DAGEngineError(f"Cannot resolve source tip '{source_tip}': {exc}") from exc

        try:
            full_last_pub_a = self.source_git.rev_parse(last_published_a)
        except GitError as exc:
            raise DAGEngineError(
                f"Cannot resolve last published A commit '{last_published_a}': {exc}"
            ) from exc

        if not self.source_git.merge_base_is_ancestor(full_last_pub_a, full_source_tip):
            raise DAGEngineError(
                f"Source history diverged: '{full_last_pub_a}' is not an ancestor of source tip '{full_source_tip}'"
            )

        commits_in_s = self.source_git.rev_list_topo(full_last_pub_a, full_source_tip)
        set_s = set(commits_in_s)
        parents_by_commit = {
            commit: self.source_git.get_commit_parents(commit) for commit in commits_in_s
        }
        if enforce_linear:
            _validate_linear_chain(
                commits_in_s, parents_by_commit, full_last_pub_a, full_source_tip
            )

        boundary_b = {
            parent
            for parents in parents_by_commit.values()
            for parent in parents
            if parent not in set_s
        }
        missing_parents = sorted(parent for parent in boundary_b if parent not in self.commit_map)
        if missing_parents:
            raise DAGEngineError(
                f"External parent boundary check failed! Missing mapping for parent commit(s): {missing_parents}. "
                f"Replay cannot proceed without valid boundary parents."
            )

        return commits_in_s, boundary_b


class BidirectionalDAGPlanner:
    def __init__(
        self,
        git_a: GitAdapter,
        git_b: GitAdapter,
        commit_map: Dict[str, str],
        reverse_map: Dict[str, List[str]],
    ):
        self.git_a = git_a
        self.git_b = git_b
        self.commit_map = commit_map
        self.reverse_map = reverse_map

    def determine_sync_state(
        self,
        tip_a: str,
        tip_b: str,
        last_a: str,
        last_b: str,
        requested_direction: str = "auto",
        enforce_phase1_linear: bool = True,
    ) -> dict:
        a_is_ff = (tip_a == last_a) or self.git_a.merge_base_is_ancestor(last_a, tip_a)
        b_is_ff = (tip_b == last_b) or self.git_b.merge_base_is_ancestor(last_b, tip_b)
        if not a_is_ff or not b_is_ff:
            raise HistoryRewrittenError(
                f"S4_REWRITTEN_HALT: Repo A fast-forward={a_is_ff}, "
                f"Repo B fast-forward={b_is_ff}; published history was rewritten or removed"
            )

        a_advanced = tip_a != last_a
        b_advanced = tip_b != last_b
        if a_advanced and b_advanced:
            # An explicitly requested direction must never bypass this halt.
            raise ConcurrentDivergenceError(
                "S3_CONCURRENT_HALT: Both Repo A and Repo B advanced concurrently; "
                "manual reconciliation is required regardless of requested direction"
            )
        if not a_advanced and not b_advanced:
            return {"state": "S0_UP_TO_DATE", "direction": None, "commits": []}

        if a_advanced:
            if requested_direction == "b2a":
                raise DAGEngineError("Direction mismatch: requested b2a but only Repo A has pending commits")
            commits_a, boundary_a = DAGBuilder(
                self.git_a, self.git_b, self.commit_map
            ).compute_sync_plan(tip_a, last_a, enforce_linear=enforce_phase1_linear)
            return {
                "state": "S1_FORWARD_A2B",
                "direction": "A2B",
                "commits": commits_a,
                "boundary": boundary_a,
            }

        if requested_direction == "a2b":
            raise DAGEngineError("Direction mismatch: requested a2b but only Repo B has pending commits")
        if (
            self.commit_map.get(last_a) != last_b
            or last_a not in self.reverse_map.get(last_b, [])
        ):
            raise DAGEngineError(
                f"Reverse anchor check failed: ({last_a}, {last_b}) must be verified "
                "by both commit_map and reverse_map"
            )

        commits_b = self.git_b.rev_list_topo(last_b, tip_b)
        parents_by_commit = {
            commit: self.git_b.get_commit_parents(commit) for commit in commits_b
        }
        # Reverse replay is strictly linear even for legacy forward DAG callers.
        _validate_linear_chain(commits_b, parents_by_commit, last_b, tip_b)
        return {
            "state": "S2_REVERSE_B2A",
            "direction": "B2A",
            "commits": commits_b,
            "boundary": {last_b},
        }
