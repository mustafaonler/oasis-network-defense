#!/usr/bin/env python3
"""OASIS explainer v0: read-only agent that explains responder decisions.

Never touches the firewall. Reads block events from SQLite, sends only
numeric/enum fields to the LLM, stores the explanation next to the event.
Usage: python src/explainer.py [--mock] [--watch]
"""
import json
import os
import re
import sqlite3
import sys
import time

DB_FILE = "data/oasis.db"
MODELS = {"gemini": os.environ.get("OASIS_MODEL", "gemini-2.5-flash"),
          "anthropic": os.environ.get("OASIS_MODEL", "claude-haiku-5-5")}
NUM_KEYS = ("packet_count", "syn_count", "unique_ports", "unique_dst_ips",
            "syn_per_second")
THRESHOLDS = {"port_scan": {"min_unique_ports": 20},
              "syn_flood": {"min_syn_per_second": 50}}
SYSTEM = (
    "You are a SOC assistant inside an autonomous network defense system. "
    "You receive one event as JSON with numeric fields only. Explain in Turkish, "
    "in 3-4 short sentences, why the traffic was classified as this attack "
    "and why this block duration was chosen. Use ONLY the numbers given. "
    "Do not invent facts, do not give commands, do not suggest actions."
)


def load_env(path=".env"):
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def open_db():
    db = sqlite3.connect(DB_FILE, timeout=10)
    db.execute("CREATE TABLE IF NOT EXISTS explanations ("
               "event_id INTEGER PRIMARY KEY, ts TEXT, model TEXT, text TEXT)")
    db.commit()
    return db


def pending(db):
    return db.execute(
        "SELECT id, ts, source_ip, attack_type, risk, action, duration_s, mode, "
        "evidence FROM events WHERE action='block' AND id NOT IN "
        "(SELECT event_id FROM explanations) ORDER BY id").fetchall()


def build_payload(row):
    _id, ts, ip, atype, risk, action, dur, mode, ev = row
    ev = json.loads(ev) if ev else {}
    return {"attack_type": atype, "risk": risk, "action": action, "mode": mode,
            "block_duration_seconds": dur if dur else "until_manual_unblock",
            "evidence": {k: ev.get(k) for k in NUM_KEYS},
            "rule_threshold": THRESHOLDS.get(atype, {})}


def template_text(p):
    e, t = p["evidence"], p["rule_threshold"]
    if p["attack_type"] == "port_scan":
        why = (f"Tek bir 5 saniyelik pencerede {e['unique_ports']} farklı porta SYN "
               f"gönderildi (eşik {t.get('min_unique_ports')}). Normal kullanımda "
               "bu sayı 1-3 civarındadır, bu yüzden port taraması sayıldı.")
    elif p["attack_type"] == "syn_flood":
        why = (f"{e['unique_ports']} porta saniyede {e['syn_per_second']} SYN "
               f"gönderildi (eşik {t.get('min_syn_per_second')} SYN/sn). "
               "Tek porta bu hız SYN Flood belirtisidir.")
    else:
        why = "Kural eşiği aşıldı."
    d = p["block_duration_seconds"]
    dur = "elle kaldırılana kadar" if d == "until_manual_unblock" else f"{d // 60} dakika"
    return f"{why} Risk seviyesi {p['risk']}, kaynak {dur} engellendi."


def llm_text_gemini(p, model):
    from google import genai
    from google.genai import types
    client = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
    r = client.models.generate_content(
        model=model, contents=json.dumps(p),
        config=types.GenerateContentConfig(
            system_instruction=SYSTEM, max_output_tokens=4000, temperature=0))
    if not r.text:
        raise ValueError("empty response")
    reason = str(r.candidates[0].finish_reason) if r.candidates else ""
    if "STOP" not in reason:
        raise ValueError("incomplete response: " + reason)
    return r.text.strip()


def llm_text_anthropic(p, model):
    import anthropic
    client = anthropic.Anthropic(timeout=20)
    msg = client.messages.create(
        model=model, max_tokens=400, system=SYSTEM,
        messages=[{"role": "user", "content": json.dumps(p)}])
    return msg.content[0].text.strip()


def pick_provider():
    if os.environ.get("GEMINI_API_KEY"):
        return "gemini"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    return None


WINDOW_SECONDS = 5


def allowed_numbers(p):
    nums = {float(WINDOW_SECONDS)}
    for v in p["evidence"].values():
        if isinstance(v, (int, float)):
            nums.add(float(v))
    for v in p["rule_threshold"].values():
        nums.add(float(v))
    d = p["block_duration_seconds"]
    if isinstance(d, (int, float)):
        nums.add(float(d))
        nums.add(d / 60)
    return nums


def verify(text, p):
    """Return the numbers in text that the evidence does not back."""
    allowed = allowed_numbers(p)
    bad = []
    for tok in re.findall(r"\d+(?:[.,]\d+)?", text):
        val = float(tok.replace(",", "."))
        if not any(abs(val - a) < 1e-9 for a in allowed):
            bad.append(tok)
    return bad


def explain(p, mock):
    provider = None if mock else pick_provider()
    if provider is None:
        return "mock", template_text(p)
    model = MODELS[provider]
    try:
        fn = llm_text_gemini if provider == "gemini" else llm_text_anthropic
        text = fn(p, model)
    except Exception as e:
        return "mock(fallback)", template_text(p) + f" [LLM hatasi: {type(e).__name__}]"
    bad = verify(text, p)
    if bad:
        return "mock(fallback)", template_text(p) + " [Dogrulama basarisiz, kanitta olmayan sayilar: " + ", ".join(bad) + "]"
    return f"{provider}:{model} (verified)", text


def run_once(db, mock):
    for row in pending(db):
        p = build_payload(row)
        model, text = explain(p, mock)
        db.execute("INSERT INTO explanations VALUES (?,?,?,?)",
                   (row[0], time.strftime("%Y-%m-%dT%H:%M:%S"), model, text))
        db.commit()
        dur = row[6] if row[6] else "manual"
        print(f"\n#{row[0]} {row[1]} {row[3]} risk={row[4]} -> {row[5]} {dur} [{row[7]}]")
        print("Kanıt:", json.dumps(p["evidence"]))
        print(f"Açıklama [{model}]: {text}", flush=True)


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
