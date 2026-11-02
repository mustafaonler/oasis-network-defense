#!/usr/bin/env python3
"""OASIS explainer v0: read-only agent that explains responder decisions.

Never touches the firewall. Reads block events from SQLite, sends only
numeric/enum fields to the LLM, stores the explanation next to the event.
Usage: python src/explainer.py [--mock] [--watch]
"""
import json
import os
import sqlite3
import sys
import time

DB_FILE = "data/oasis.db"
MODEL = os.environ.get("OASIS_MODEL", "claude-haiku-5-5")
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


def llm_text(p):
    import anthropic
    client = anthropic.Anthropic(timeout=20)
    msg = client.messages.create(
        model=MODEL, max_tokens=400, system=SYSTEM,
        messages=[{"role": "user", "content": json.dumps(p)}])
    return msg.content[0].text.strip()


def explain(p, mock):
    if mock or not os.environ.get("ANTHROPIC_API_KEY"):
        return "mock", template_text(p)
    try:
        return MODEL, llm_text(p)
    except Exception as e:
        return "mock(fallback)", template_text(p) + f" [LLM hatası: {type(e).__name__}]"


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
