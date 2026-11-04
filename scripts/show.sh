#!/usr/bin/env bash
# Print every event with its LLM explanation and specialist opinion.
cd "$(dirname "$0")/.." || exit 1
python3 - <<'PY'
import json, sqlite3
db = sqlite3.connect("data/oasis.db")
ex = {r[0]: r[1] for r in db.execute("select event_id, text from explanations")}
try:
    an = {r[0]: r[1:] for r in db.execute(
        "select event_id, agent, verdict, confidence, risk_opinion, reasons from analyses")}
except sqlite3.OperationalError:
    an = {}
q = "select id, ts, source_ip, attack_type, risk, action, duration_s from events order by id"
for r in db.execute(q):
    print(f"#{r[0]} {r[1]} {r[2]} {r[3]} risk={r[4]} action={r[5]} duration={r[6]}")
    if r[0] in an:
        agent, verdict, conf, risk, reasons = an[r[0]]
        print(f"    [{agent}] görüş: {verdict} (güven: {conf}), risk önerisi: {risk}")
        for x in json.loads(reasons):
            print("      -", x)
    if r[0] in ex:
        print("    Açıklama:", ex[r[0]])
PY
