"""Tests for inference/relationship_llm.py.

Per the master spec's testing strategy for Phases C-F: "never test
against a live model call in CI. Instead, test that (a) prompts are
built correctly from given inputs [see test_prompts.py], and (b) a set
of fixture LLM *responses* (including deliberately malformed ones) are
handled correctly by your schema validation and storage code." That is
exactly what this file does -- every test here monkeypatches
relationship_llm.call_llm with a canned string instead of hitting a
model.
"""

import json

import pytest

from attackmapper import storage
from attackmapper.inference import relationship_llm
from attackmapper.models import Edge
from attackmapper.storage import InMemoryStore

# ---------------------------------------------------------------------
# parse_relationship_response: schema validation against fixture
# responses, no storage or LLM involved.
# ---------------------------------------------------------------------


def test_parses_well_formed_response():
    raw = json.dumps(
        {
            "relationships": [
                {
                    "source": "app",
                    "target": "db",
                    "relationship_type": "CAN_ACCESS",
                    "evidence": "finding #12",
                    "confidence": 0.9,
                }
            ]
        }
    )
    result = relationship_llm.parse_relationship_response(raw)
    assert result == [
        {
            "source": "app",
            "target": "db",
            "relationship_type": "CAN_ACCESS",
            "evidence": "finding #12",
            "confidence": 0.9,
        }
    ]


def test_rejects_non_json_entirely():
    assert relationship_llm.parse_relationship_response("not json at all") == []


def test_rejects_response_missing_top_level_key():
    raw = json.dumps({"edges": []})  # wrong key
    assert relationship_llm.parse_relationship_response(raw) == []


def test_rejects_relationships_that_is_not_a_list():
    raw = json.dumps({"relationships": "oops"})
    assert relationship_llm.parse_relationship_response(raw) == []


def test_skips_items_missing_required_fields_but_keeps_valid_ones():
    raw = json.dumps(
        {
            "relationships": [
                {"source": "app", "target": "db"},  # missing fields
                {
                    "source": "web",
                    "target": "app",
                    "relationship_type": "CAN_REACH",
                    "evidence": "ok",
                    "confidence": 0.5,
                },
            ]
        }
    )
    result = relationship_llm.parse_relationship_response(raw)
    assert len(result) == 1
    assert result[0]["source"] == "web"


def test_skips_items_with_out_of_range_confidence():
    raw = json.dumps(
        {
            "relationships": [
                {
                    "source": "a",
                    "target": "b",
                    "relationship_type": "CAN_REACH",
                    "evidence": "ev",
                    "confidence": 1.5,
                }
            ]
        }
    )
    assert relationship_llm.parse_relationship_response(raw) == []


def test_skips_items_with_non_numeric_confidence():
    raw = json.dumps(
        {
            "relationships": [
                {
                    "source": "a",
                    "target": "b",
                    "relationship_type": "CAN_REACH",
                    "evidence": "ev",
                    "confidence": "high",
                }
            ]
        }
    )
    assert relationship_llm.parse_relationship_response(raw) == []


def test_skips_items_with_non_string_source():
    raw = json.dumps(
        {
            "relationships": [
                {
                    "source": 123,
                    "target": "b",
                    "relationship_type": "CAN_REACH",
                    "evidence": "ev",
                    "confidence": 0.5,
                }
            ]
        }
    )
    assert relationship_llm.parse_relationship_response(raw) == []


def test_empty_relationships_list_is_valid():
    raw = json.dumps({"relationships": []})
    assert relationship_llm.parse_relationship_response(raw) == []


def test_low_confidence_items_are_not_filtered_by_schema_validation():
    """Per the spec: 'do not silently drop low-confidence ones' --
    that's a job for load_graph(min_confidence=...) downstream, not
    schema validation."""
    raw = json.dumps(
        {
            "relationships": [
                {
                    "source": "a",
                    "target": "b",
                    "relationship_type": "CAN_REACH",
                    "evidence": "ev",
                    "confidence": 0.01,
                }
            ]
        }
    )
    result = relationship_llm.parse_relationship_response(raw)
    assert len(result) == 1
    assert result[0]["confidence"] == 0.01


# ---------------------------------------------------------------------
# infer_relationships: the full pipeline, LLM call mocked out.
# ---------------------------------------------------------------------


@pytest.fixture
def fresh_store(monkeypatch):
    store = InMemoryStore(seed_demo_data=False)
    monkeypatch.setattr(storage, "_default_store", store)
    return store


def test_infer_relationships_stores_valid_proposals_as_unconfirmed(
    fresh_store, monkeypatch
):
    host_id = fresh_store.save_host({"hostname": "app01", "ip": "10.0.2.10"})
    fresh_store.save_finding(
        {
            "host_id": host_id,
            "type": "leaked_credential",
            "severity": "high",
            "description": "leaked DB creds",
            "evidence": "finding evidence",
        }
    )

    fake_response = json.dumps(
        {
            "relationships": [
                {
                    "source": host_id,
                    "target": "db",
                    "relationship_type": "CAN_ACCESS",
                    "evidence": "leaked creds grant DB access",
                    "confidence": 0.8,
                }
            ]
        }
    )
    monkeypatch.setattr(relationship_llm, "call_llm", lambda prompt: fake_response)

    edges = relationship_llm.infer_relationships()

    assert len(edges) == 1
    edge = edges[0]
    assert edge.source == host_id
    assert edge.target == "db"
    assert edge.relationship == "CAN_ACCESS"
    assert edge.confirmed is False
    assert edge.proposed_by == "llm"
    assert edge.confidence == 0.8

    # And it actually landed in storage, filterable via min_confidence.
    stored = fresh_store.list_relationships(confirmed=False)
    assert len(stored) == 1
    assert stored[0]["proposed_by"] == "llm"


def test_infer_relationships_skips_llm_call_when_no_findings(fresh_store, monkeypatch):
    called = []
    monkeypatch.setattr(
        relationship_llm, "call_llm", lambda prompt: called.append(1) or "{}"
    )
    edges = relationship_llm.infer_relationships()
    assert edges == []
    assert called == []  # never even called the model


def test_infer_relationships_stores_nothing_on_malformed_response(
    fresh_store, monkeypatch
):
    fresh_store.save_finding(
        {
            "host_id": fresh_store.save_host({"hostname": "h", "ip": "10.0.0.1"}),
            "type": "weak_password",
            "severity": "low",
            "description": "d",
            "evidence": "e",
        }
    )
    monkeypatch.setattr(relationship_llm, "call_llm", lambda prompt: "not json")

    edges = relationship_llm.infer_relationships()
    assert edges == []
    assert fresh_store.list_relationships() == []


def test_infer_relationships_accepts_caller_supplied_findings(fresh_store, monkeypatch):
    """A caller can pass a specific findings subset instead of pulling
    everything from storage (e.g. a targeted re-run)."""
    fake_response = json.dumps(
        {
            "relationships": [
                {
                    "source": "external",
                    "target": "web",
                    "relationship_type": "CAN_REACH",
                    "evidence": "ev",
                    "confidence": 1.0,
                }
            ]
        }
    )
    monkeypatch.setattr(relationship_llm, "call_llm", lambda prompt: fake_response)

    custom_findings = [
        {
            "host_id": "web",
            "type": "open_port",
            "severity": "low",
            "description": "d",
            "evidence": "e",
        }
    ]
    edges = relationship_llm.infer_relationships(findings=custom_findings)
    assert len(edges) == 1


# ---------------------------------------------------------------------
# compare_proposed_to_confirmed: the Phase C sanity-check report.
# ---------------------------------------------------------------------


def test_compare_buckets_agree_contradict_and_novel(fresh_store):
    fresh_store.save_relationship(
        Edge(
            source="app",
            target="db",
            relationship="CAN_ACCESS",
            evidence="hand-verified",
            confirmed=True,
            confidence=1.0,
            proposed_by="manual",
        )
    )

    proposed = [
        Edge(  # agrees: same pair, same type
            source="app",
            target="db",
            relationship="CAN_ACCESS",
            evidence="llm ev",
            confirmed=False,
            confidence=0.7,
            proposed_by="llm",
        ),
        Edge(  # contradicts: same pair, different type
            source="app",
            target="db",
            relationship="RUNS_AS",
            evidence="llm ev",
            confirmed=False,
            confidence=0.6,
            proposed_by="llm",
        ),
        Edge(  # novel: no confirmed edge for this pair
            source="web",
            target="app",
            relationship="CAN_REACH",
            evidence="llm ev",
            confirmed=False,
            confidence=0.5,
            proposed_by="llm",
        ),
    ]

    report = relationship_llm.compare_proposed_to_confirmed(proposed)
    assert len(report["agrees"]) == 1
    assert len(report["contradicts"]) == 1
    assert len(report["novel"]) == 1
    assert report["agrees"][0].relationship == "CAN_ACCESS"
    assert report["contradicts"][0].relationship == "RUNS_AS"
    assert report["novel"][0].source == "web"


def test_compare_pulls_from_storage_when_not_given_explicitly(fresh_store):
    fresh_store.save_relationship(
        Edge(
            source="a",
            target="b",
            relationship="CAN_REACH",
            confirmed=True,
            confidence=1.0,
            proposed_by="manual",
        )
    )
    fresh_store.save_relationship(
        Edge(
            source="a",
            target="b",
            relationship="CAN_REACH",
            confirmed=False,
            confidence=0.5,
            proposed_by="llm",
        )
    )
    # A confirmed, non-llm-proposed edge should never show up as "proposed".
    fresh_store.save_relationship(
        Edge(
            source="c",
            target="d",
            relationship="CAN_REACH",
            confirmed=True,
            confidence=1.0,
            proposed_by="discovery",
        )
    )

    report = relationship_llm.compare_proposed_to_confirmed()
    assert len(report["agrees"]) == 1
    assert len(report["contradicts"]) == 0
    assert len(report["novel"]) == 0


def test_call_llm_raises_clear_error_without_api_key(monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    import sys
    import types

    fake_openai = types.ModuleType("openai")
    fake_openai.OpenAI = object  # present so the lazy import succeeds
    monkeypatch.setitem(sys.modules, "openai", fake_openai)
    with pytest.raises(RuntimeError, match="OPENROUTER_API_KEY"):
        relationship_llm.call_llm("a prompt")
