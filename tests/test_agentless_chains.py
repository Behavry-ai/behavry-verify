"""Behavry AG-13 E-10: agentless decision chains, checked by their links.

Agentless decisions (no agent_id) chain per scope (device, else user, else
tenant). Replayed client events make timestamp order differ from link order,
so a scope must form one path: no fork, no hole except one at the window edge.
"""
from __future__ import annotations

from behavry_verify.package import agentless_tag, walk_event_chain


def ev(id_, ts, h, prev, **kw):
    base = {"id": id_, "tenant_id": "t1", "agent_id": None, "claim_type": None,
            "timestamp": ts, "event_hash": h, "previous_hash": prev}
    return base | kw


def test_a_linked_device_chain_passes():
    events = [ev("a", "1", "h1", None, device_id="d1"), ev("b", "2", "h2", "h1", device_id="d1"),
              ev("c", "3", "h3", "h2", device_id="d1")]
    assert walk_event_chain(events) == []


def test_a_replay_dated_earlier_than_its_link_order_passes():
    # c was captured offline before b but recorded after it, so it links to b.
    events = [ev("a", "1", "h1", None, device_id="d1"), ev("b", "3", "h2", "h1", device_id="d1"),
              ev("c", "2", "h3", "h2", device_id="d1")]
    assert walk_event_chain(events) == []


def test_a_deleted_event_in_the_middle_is_found():
    # b (h2) deleted: c names a missing predecessor, as does the window edge a.
    events = [ev("a", "1", "h1", "h0", device_id="d1"), ev("c", "3", "h3", "h2", device_id="d1")]
    breaks = walk_event_chain(events)
    assert len(breaks) == 1 and "missing the predecessor" in breaks[0]


def test_one_hole_at_the_window_edge_is_allowed():
    events = [ev("b", "2", "h2", "h1", device_id="d1"), ev("c", "3", "h3", "h2", device_id="d1")]
    assert walk_event_chain(events) == []


def test_a_fork_is_found():
    events = [ev("a", "1", "h1", None, device_id="d1"), ev("b", "2", "h2", "h1", device_id="d1"),
              ev("x", "3", "hx", "h1", device_id="d1")]
    breaks = walk_event_chain(events)
    assert len(breaks) == 1 and "forks" in breaks[0]


def test_unlinked_history_rows_pass():
    events = [ev(f"e{i}", str(i), f"h{i}", None) for i in range(5)]
    assert walk_event_chain(events) == []


def test_scopes_are_separate():
    # A device chain and a user chain in one tenant are two chains, not one.
    events = [ev("a", "1", "h1", None, device_id="d1"), ev("b", "2", "h2", "h1", device_id="d1"),
              ev("u", "3", "u1", None, user_identifier="alice@example.com"),
              ev("v", "4", "u2", "u1", user_identifier="alice@example.com")]
    assert walk_event_chain(events) == []


def test_the_exported_tag_groups_a_redacted_user_chain():
    tag = agentless_tag({"user_identifier": "alice@example.com"})
    assert tag.startswith("usr:") and len(tag) == 20
    # The same chain with user_identifier withheld, grouped by its exported tag.
    events = [
        ev("u", "3", "u1", None, agentless_chain=tag),
        ev("v", "4", "u2", "u1", agentless_chain=tag),
        ev("t", "5", "t1", None),
    ]
    assert walk_event_chain(events) == []
