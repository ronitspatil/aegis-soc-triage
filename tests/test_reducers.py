"""State channel reducers: what makes the parallel fan-out legal."""

from __future__ import annotations

import operator
from typing import get_args, get_type_hints

from aegis.schemas.state import SOCAgentState, union_strings


def test_union_reducer_deduplicates_across_agents():
    """Two agents independently observing T1078 must not double-count it."""
    assert union_strings(["T1078", "T1110"], ["T1078", "T1059"]) == [
        "T1059", "T1078", "T1110"
    ]


def test_concatenation_would_have_duplicated():
    """Documents WHY operator.add is wrong for this channel."""
    assert operator.add(["T1078"], ["T1078"]) == ["T1078", "T1078"]


def test_enrichments_channel_has_a_reducer():
    """Without one, three concurrent writes raise InvalidUpdateError."""
    hints = get_type_hints(SOCAgentState, include_extras=True)
    assert operator.add in get_args(hints["enrichments"])


def test_audit_log_is_append_only():
    hints = get_type_hints(SOCAgentState, include_extras=True)
    assert operator.add in get_args(hints["audit_log"])
