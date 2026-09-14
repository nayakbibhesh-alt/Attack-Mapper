"""Core data types shared by every layer.

These shapes are the contract: layers above Storage depend on Node and
Edge looking exactly like this, and nothing else. Do not add fields
that leak implementation details of a particular layer (e.g. no
"scanner_raw_output" field here — that belongs in Finding/evidence).
"""

from dataclasses import dataclass, field


@dataclass
class Node:
    id: str
    type: str          # 'external' | 'host' | 'account' | 'asset'
    label: str = ""

    def __post_init__(self) -> None:
        valid_types = {"external", "host", "account", "asset"}
        if self.type not in valid_types:
            raise ValueError(
                f"Node.type must be one of {valid_types}, got {self.type!r}"
            )


@dataclass
class Edge:
    source: str
    target: str
    relationship: str
    evidence: str = ""
    confirmed: bool = True          # False for LLM-proposed, unverified edges
    confidence: float = 1.0         # 1.0 for deterministic/confirmed evidence
    proposed_by: str = "discovery"  # 'discovery' | 'llm' | 'manual'

    def __post_init__(self) -> None:
        valid_proposers = {"discovery", "llm", "manual"}
        if self.proposed_by not in valid_proposers:
            raise ValueError(
                f"Edge.proposed_by must be one of {valid_proposers}, "
                f"got {self.proposed_by!r}"
            )
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"Edge.confidence must be in [0.0, 1.0], got {self.confidence!r}"
            )
        # A deterministic invariant worth enforcing at construction time:
        # confirmed edges are, by definition, fully confident. This is not
        # in the written spec as a hard rule, but relaxing it would let an
        # edge claim confirmed=True while still hedging with confidence<1.0,
        # which defeats the whole point of the confirmed/confidence split.
        if self.confirmed and self.confidence < 1.0:
            raise ValueError(
                "Edge.confirmed=True requires confidence=1.0 "
                "(confirmed edges are not hedged)"
            )


@dataclass
class Finding:
    """Mirrors the `findings` table. Kept here (rather than only as a
    dict) so discovery/inference code gets type-checking, but storage.py
    still accepts/returns plain dicts per the spec's save_finding(dict)
    signature — call Finding.__dict__ / dataclasses.asdict() at that
    boundary.
    """

    host_id: str
    type: str
    severity: str        # 'low' | 'medium' | 'high' | 'critical'
    description: str
    evidence: str
    source: str = "scanner"    # 'scanner' | 'llm_inferred' | 'manual'
    confidence: float = 1.0    # 1.0 for scanner-confirmed
    id: str = field(default="")
