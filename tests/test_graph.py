"""Pure unit tests for AttackGraph. No infra, no storage, no LLM —
just hand-built Node/Edge lists covering the cases called out in the
spec's testing strategy: disconnected graphs, cyclic graphs,
multi-path graphs, and zero-path cases.
"""

import pytest

from attackmapper.graph import AttackGraph
from attackmapper.models import Edge, Node


def edge(source, target, relationship="CAN_REACH", **kwargs):
    return Edge(source=source, target=target, relationship=relationship, **kwargs)


def test_simple_linear_path():
    nodes = [Node(id=x, type="host") for x in ["a", "b", "c"]]
    edges = [edge("a", "b"), edge("b", "c")]
    g = AttackGraph(nodes, edges)
    paths = g.find_all_paths("a", "c")
    assert len(paths) == 1
    assert [e.source for e in paths[0]] == ["a", "b"]
    assert [e.target for e in paths[0]] == ["b", "c"]


def test_zero_path_disconnected_graph():
    nodes = [Node(id=x, type="host") for x in ["a", "b", "c", "d"]]
    edges = [edge("a", "b")]  # c and d are isolated
    g = AttackGraph(nodes, edges)
    assert g.find_all_paths("a", "c") == []
    assert g.find_all_paths("a", "d") == []
    assert g.find_all_paths("c", "d") == []


def test_zero_path_unknown_nodes():
    nodes = [Node(id="a", type="host"), Node(id="b", type="host")]
    edges = [edge("a", "b")]
    g = AttackGraph(nodes, edges)
    assert g.find_all_paths("a", "nonexistent") == []
    assert g.find_all_paths("nonexistent", "b") == []


def test_zero_path_start_equals_target():
    nodes = [Node(id="a", type="host")]
    g = AttackGraph(nodes, [])
    assert g.find_all_paths("a", "a") == []


def test_multi_path_graph_finds_all_routes():
    # a -> b -> d
    # a -> c -> d
    nodes = [Node(id=x, type="host") for x in ["a", "b", "c", "d"]]
    edges = [edge("a", "b"), edge("b", "d"), edge("a", "c"), edge("c", "d")]
    g = AttackGraph(nodes, edges)
    paths = g.find_all_paths("a", "d")
    assert len(paths) == 2
    routes = {tuple(e.target for e in p) for p in paths}
    assert routes == {("b", "d"), ("c", "d")}


def test_cyclic_graph_does_not_infinite_loop_and_finds_simple_paths():
    # a -> b -> c -> a (cycle), and c -> d (the actual target)
    nodes = [Node(id=x, type="host") for x in ["a", "b", "c", "d"]]
    edges = [edge("a", "b"), edge("b", "c"), edge("c", "a"), edge("c", "d")]
    g = AttackGraph(nodes, edges)
    paths = g.find_all_paths("a", "d")
    assert len(paths) == 1
    assert [e.target for e in paths[0]] == ["b", "c", "d"]


def test_cyclic_graph_with_multiple_exits():
    # a -> b -> c -> a (cycle); both b and c can also reach target t
    nodes = [Node(id=x, type="host") for x in ["a", "b", "c", "t"]]
    edges = [
        edge("a", "b"),
        edge("b", "c"),
        edge("c", "a"),
        edge("b", "t"),
        edge("c", "t"),
    ]
    g = AttackGraph(nodes, edges)
    paths = g.find_all_paths("a", "t")
    routes = {tuple(e.target for e in p) for p in paths}
    assert routes == {("b", "t"), ("b", "c", "t")}


def test_describe_path_formats_confirmed_chain():
    nodes = [Node(id=x, type="host") for x in ["a", "b"]]
    edges = [edge("a", "b", relationship="CAN_ACCESS")]
    g = AttackGraph(nodes, edges)
    [path] = g.find_all_paths("a", "b")
    assert g.describe_path(path) == "a --CAN_ACCESS--> b"


def test_describe_path_flags_unconfirmed_edges():
    nodes = [Node(id=x, type="host") for x in ["a", "b"]]
    edges = [
        edge(
            "a",
            "b",
            relationship="CAN_ACCESS",
            confirmed=False,
            confidence=0.5,
            proposed_by="llm",
        )
    ]
    g = AttackGraph(nodes, edges)
    [path] = g.find_all_paths("a", "b")
    desc = g.describe_path(path)
    assert "unconfirmed" in desc
    assert "0.50" in desc


def test_describe_path_empty_path_returns_empty_string():
    g = AttackGraph([], [])
    assert g.describe_path([]) == ""


def test_path_confidence_is_product_of_edge_confidences():
    e1 = edge("a", "b", confidence=1.0)
    e2 = edge(
        "b", "c", confirmed=False, confidence=0.5, proposed_by="llm"
    )
    assert AttackGraph.path_confidence([e1, e2]) == pytest.approx(0.5)


def test_path_confidence_empty_path_is_zero():
    assert AttackGraph.path_confidence([]) == 0.0


def test_multiple_edges_between_same_pair_both_considered():
    # Two different relationship types between the same hosts should
    # both be walkable, and show up as distinct paths.
    nodes = [Node(id=x, type="host") for x in ["a", "b"]]
    edges = [
        edge("a", "b", relationship="CAN_REACH"),
        edge("a", "b", relationship="CAN_ACCESS"),
    ]
    g = AttackGraph(nodes, edges)
    paths = g.find_all_paths("a", "b")
    assert len(paths) == 2
    rels = {p[0].relationship for p in paths}
    assert rels == {"CAN_REACH", "CAN_ACCESS"}
