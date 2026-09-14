"""graph.py — unchanged from the deterministic core, LLM-agnostic.

Builds an adjacency structure from Node/Edge lists (Layer 4: Graph
Engine) and enumerates attack paths over it (Layer 5: Path Finder).
No knowledge of scanners, Postgres, or LLMs lives here, and nothing
here ever makes a network or model call. This module should not need
to change as the rest of the system grows.
"""

from __future__ import annotations

from collections import defaultdict

from .models import Edge, Node


class AttackGraph:
    def __init__(self, nodes: list[Node], edges: list[Edge]) -> None:
        self.nodes: dict[str, Node] = {n.id: n for n in nodes}
        self.edges: list[Edge] = list(edges)
        self._adjacency: dict[str, list[Edge]] = defaultdict(list)
        for e in self.edges:
            self._adjacency[e.source].append(e)

    def find_all_paths(self, start: str, target: str) -> list[list[Edge]]:
        """Depth-first enumeration of every simple path (no repeated
        node) from `start` to `target`. Returns [] if either node is
        absent from the graph, if start == target, or if no path
        exists. Cycles in the underlying graph are handled by tracking
        visited nodes on the current path, not by any global visited
        set, so all simple paths are still found even across a cyclic
        graph.
        """
        if start not in self.nodes or target not in self.nodes:
            return []
        if start == target:
            return []

        paths: list[list[Edge]] = []
        visited: set[str] = {start}

        def dfs(current: str, path_so_far: list[Edge]) -> None:
            if current == target:
                paths.append(list(path_so_far))
                return
            for edge in self._adjacency.get(current, []):
                if edge.target in visited:
                    continue  # would revisit a node -> not a simple path
                visited.add(edge.target)
                path_so_far.append(edge)
                dfs(edge.target, path_so_far)
                path_so_far.pop()
                visited.remove(edge.target)

        dfs(start, [])
        return paths

    def describe_path(self, path: list[Edge]) -> str:
        """Render a path as a single human-readable chain, e.g.:
        external --CAN_REACH--> web --CAN_REACH--> app --RUNS_AS--> svc_account
        Returns an empty string for an empty path.
        """
        if not path:
            return ""
        parts = [path[0].source]
        for edge in path:
            marker = f"--{edge.relationship}-->" if edge.confirmed else (
                f"~~{edge.relationship}~~(unconfirmed, conf={edge.confidence:.2f})~~>"
            )
            parts.append(marker)
            parts.append(edge.target)
        return " ".join(parts)

    @staticmethod
    def path_confidence(path: list[Edge]) -> float:
        """Pure arithmetic, not an LLM call: a path's overall confidence
        is the product of its edges' confidence. An empty path has
        confidence 0.0 (there is no path)."""
        if not path:
            return 0.0
        confidence = 1.0
        for edge in path:
            confidence *= edge.confidence
        return confidence
