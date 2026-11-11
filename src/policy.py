#!/usr/bin/env python3
"""OASIS block policy: the action ladder shared by the responder and the agents.

No firewall code here, so the LLM agents can import it without loading nft logic.
"""

START_STEP = {"medium": 0, "high": 1}
LADDER = [300, 1800, None]   # seconds; None = until removed manually
REPEAT_WINDOW = 3600         # seconds: a repeat offender escalates


def prior_blocks(db, ip, mode, epoch):
    """Blocks of this source in the REPEAT_WINDOW before epoch, as the responder counts them."""
    return db.execute(
        "SELECT COUNT(*) FROM events WHERE source_ip=? AND action='block' "
        "AND mode=? AND epoch>? AND epoch<?",
        (ip, mode, epoch - REPEAT_WINDOW, epoch)).fetchone()[0]


def repeat_rule(db, ip, mode, epoch, risk, duration_s):
    """Numeric facts behind a block's duration. Safe to send to an LLM: no IP in it."""
    return {
        "prior_blocks_last_hour": prior_blocks(db, ip, mode, epoch),
        "start_step_for_risk": START_STEP.get(risk, 0),
        "applied_step": LADDER.index(duration_s or None),
        "ladder_seconds": [s or "until_manual_unblock" for s in LADDER],
        "repeat_window_seconds": REPEAT_WINDOW,
    }
