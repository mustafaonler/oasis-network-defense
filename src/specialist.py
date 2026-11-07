#!/usr/bin/env python3
"""OASIS specialist agents v0: attack-type specialists giving a second opinion.

Advisory only: never touches the firewall and never changes the risk level.
Router (plain code) -> PortScanAgent / SynFloodAgent (LLM, JSON out) -> number
check -> SQLite. If the LLM fails or invents numbers, a rule-based opinion is
stored instead.
Usage: python src/specialist.py [--mock] [--watch]
"""
import json
import os
import re
import sqlite3
import sys
import time

import policy

DB_FILE = "data/oasis.db"
WINDOW_SECONDS = 5
NUM_KEYS = ("packet_count", "syn_count", "unique_ports", "unique_dst_ips",
            "syn_per_second")
THRESHOLDS = {"port_scan": {"min_unique_ports": 20},
              "syn_flood": {"min_syn_per_second": 50}}
# Numbers measured in our own lab tests (normal web, SSH, small scans).
LAB_BASELINE = {"normal_traffic_max_syn_per_second": 3.6,
                "normal_traffic_unique_ports": 1,
                "small_scan_ports_that_raised_no_alert": 15}
AGENTS = {"port_scan": "PortScanAgent", "syn_flood": "SynFloodAgent"}

COMMON = (
    "You are a specialist analyst in an autonomous network defense system. "
    "You get one rule-based alert as JSON with numeric fields only, plus lab "
    "baseline numbers. Give an independent second opinion. Answer ONLY with a "
    'JSON object: {"verdict": "confirm|uncertain|disagree", '
    '"confidence": "high|medium|low", "risk_opinion": "keep|raise|lower", '
    '"reasons": ["...", "..."]}. reasons: 2 or 3 short sentences in Turkish. '
    "Quote numbers exactly as given, never invent numbers, never mention IP "
    "addresses, never suggest commands or actions. current_risk is the level "
    "the rules already assigned. Fields ending in _percent are percentages: "
    "write them as percent values, for example 99.0 percent. risk_opinion: use "
    "raise only if current_risk is medium and the evidence is far stronger than "
    "the rule needs; never use raise when current_risk is high; use lower only "
    "if the evidence is weak. repeat_rule shows how often this source was already "
    "blocked in the last hour (prior_blocks_last_hour); you may use it for risk_opinion."
)
FOCUS = {
    "port_scan": (
        "Your specialty is port scans (reconnaissance). Judge: how many distinct "
        "ports were probed in one window, ports per second, the share of SYN "
        "packets, and the number of target hosts (one host = vertical scan, many "
        "hosts = horizontal scan). Compare with the lab baseline: normal traffic "
        "touches 1 port, and a small scan of 15 ports raised no alert."),
    "syn_flood": (
        "Your specialty is SYN floods (denial of service). Judge: SYN per second "
        "versus the rule threshold and versus the maximum seen in normal traffic, "
        "concentration on a single port, the share of SYN among all packets, and "
        "whether a legitimate traffic burst could explain it."),
}


def load_env(path=".env"):
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def pick_provider():
    if os.environ.get("GEMINI_API_KEY"):
        return "gemini"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    return None


def model_for(provider):
    default = "gemini-2.5-flash" if provider == "gemini" else "claude-haiku-5-5"
    return os.environ.get("OASIS_MODEL", default)


def open_db():
    db = sqlite3.connect(DB_FILE, timeout=10)
    db.execute("CREATE TABLE IF NOT EXISTS analyses ("
               "event_id INTEGER PRIMARY KEY, ts TEXT, agent TEXT, model TEXT, "
               "verdict TEXT, confidence TEXT, risk_opinion TEXT, reasons TEXT)")
    db.commit()
    return db


def pending(db):
    return db.execute(
        "SELECT id, ts, attack_type, evidence, risk, source_ip, mode, epoch, duration_s "
        "FROM events WHERE action='block' "
        "AND id NOT IN (SELECT event_id FROM analyses) ORDER BY id").fetchall()


def build_payload(atype, ev, risk="medium", repeat=None):
    e = {k: ev.get(k) for k in NUM_KEYS}
    pk, syn = e["packet_count"] or 0, e["syn_count"] or 0
    derived = {  # computed in code, so the LLM never does arithmetic
        "syn_share_percent": round(100 * syn / pk, 1) if pk else 0,
        "unique_ports_per_second": round((e["unique_ports"] or 0) / WINDOW_SECONDS, 1),
    }
    p = {"attack_type": atype, "current_risk": risk, "evidence": e,
         "derived": derived, "rule_threshold": THRESHOLDS.get(atype, {}),
         "lab_baseline": LAB_BASELINE, "window_seconds": WINDOW_SECONDS}
    if repeat is not None:
        p["repeat_rule"] = repeat
    return p


def collect(o, out):
    if isinstance(o, bool):
        return
    if isinstance(o, (int, float)):
        out.add(float(o))
    elif isinstance(o, dict):
        for v in o.values():
            collect(v, out)
    elif isinstance(o, list):
        for v in o:
            collect(v, out)


def allowed_numbers(p):
    nums = set()
    collect(p, nums)
    for v in list(nums):
        nums.add(float(round(v)))   # a rounded form may be quoted
    return nums


def unbacked(texts, p):
    """Numbers quoted in texts that the evidence does not back."""
    allowed = allowed_numbers(p)
    bad = []
    for t in texts:
        for tok in re.findall(r"\d+(?:[.,]\d+)?", t):
            val = float(tok.replace(",", "."))
            if not any(abs(val - a) < 1e-6 for a in allowed):
                bad.append(tok)
    return bad


def call_llm(provider, model, system, payload):
    if provider == "gemini":
        from google import genai
        from google.genai import types
        # v1beta: on the v1 API (google-genai 3.x default) some models reject system_instruction.
        client = genai.Client(api_key=os.environ["GEMINI_API_KEY"],
                              http_options=types.HttpOptions(timeout=20000, api_version="v1beta"))
        r = client.models.generate_content(
            model=model, contents=json.dumps(payload),
            config=types.GenerateContentConfig(
                system_instruction=system, max_output_tokens=4000, temperature=0,
                response_mime_type="application/json"))
        reason = str(r.candidates[0].finish_reason) if r.candidates else ""
        if not r.text or "STOP" not in reason:
            raise ValueError("incomplete response: " + reason)
        return r.text
    import anthropic
    client = anthropic.Anthropic(timeout=20)
    m = client.messages.create(
        model=model, max_tokens=600, system=system,
        messages=[{"role": "user", "content": json.dumps(payload)}])
    return m.content[0].text


def parse_opinion(raw):
    raw = re.sub(r"^```(?:json)?|```$", "", raw.strip(), flags=re.M).strip()
    d = json.loads(raw)
    if d.get("verdict") not in ("confirm", "uncertain", "disagree"):
        raise ValueError("bad verdict")
    if d.get("confidence") not in ("high", "medium", "low"):
        raise ValueError("bad confidence")
    if d.get("risk_opinion") not in ("keep", "raise", "lower"):
        raise ValueError("bad risk_opinion")
    reasons = [str(x).replace("`", "").replace("**", "") for x in d.get("reasons", [])][:3]
    if not reasons:
        raise ValueError("no reasons")
    return {"verdict": d["verdict"], "confidence": d["confidence"],
            "risk_opinion": d["risk_opinion"], "reasons": reasons}


def rule_opinion(atype, p):
    e, t = p["evidence"], p["rule_threshold"]
    if atype == "port_scan":
        hit = e["unique_ports"] >= t["min_unique_ports"]
        why = f"{e['unique_ports']} farklı port görüldü, kural eşiği {t['min_unique_ports']}."
    else:
        hit = e["syn_per_second"] >= t["min_syn_per_second"]
        why = f"Saniyede {e['syn_per_second']} SYN görüldü, kural eşiği {t['min_syn_per_second']}."
    return {"verdict": "confirm" if hit else "uncertain", "confidence": "medium",
            "risk_opinion": "keep", "reasons": [why]}


def analyze(atype, ev, mock, risk="medium", repeat=None):
    """Router: pick the specialist for this attack type, return its opinion."""
    if atype not in AGENTS:
        return None
    agent = AGENTS[atype]
    p = build_payload(atype, ev, risk, repeat)
    provider = None if mock else pick_provider()
    if provider is None:
        return agent, "rules", rule_opinion(atype, p)
    model = model_for(provider)
    try:
        op = parse_opinion(call_llm(provider, model, COMMON + " " + FOCUS[atype], p))
        bad = unbacked(op["reasons"], p)
        if bad:
            raise ValueError("numbers not in evidence: " + ",".join(bad))
        if risk == "high" and op["risk_opinion"] == "raise":
            op["risk_opinion"] = "keep"   # already at the top level
        return agent, f"{provider}:{model} (verified)", op
    except Exception as ex:
        return agent, f"rules(fallback:{type(ex).__name__})", rule_opinion(atype, p)


def run_once(db, mock):
    for _id, ts, atype, ev, risk, ip, mode, epoch, dur in pending(db):
        # ip is used for the local repeat count only; it never goes into the payload.
        repeat = policy.repeat_rule(db, ip, mode, epoch, risk, dur)
        res = analyze(atype, json.loads(ev) if ev else {}, mock, risk or "medium", repeat)
        if res is None:
            continue
        agent, label, op = res
        db.execute("INSERT INTO analyses VALUES (?,?,?,?,?,?,?,?)",
                   (_id, time.strftime("%Y-%m-%dT%H:%M:%S"), agent, label,
                    op["verdict"], op["confidence"], op["risk_opinion"],
                    json.dumps(op["reasons"], ensure_ascii=False)))
        db.commit()
        print(f"\n#{_id} {ts} {atype} -> {agent} [{label}]")
        print(f"  Görüş: {op['verdict']} (güven: {op['confidence']}), "
              f"risk önerisi: {op['risk_opinion']}")
        for r in op["reasons"]:
            print("  -", r, flush=True)


def main():
    load_env()
    mock = "--mock" in sys.argv
    db = open_db()
    run_once(db, mock)
    while "--watch" in sys.argv:
        time.sleep(2)
        run_once(db, mock)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Stopped.")
