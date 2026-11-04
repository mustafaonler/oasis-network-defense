#!/usr/bin/env bash
# Print every event with its LLM explanation.
cd "$(dirname "$0")/.." || exit 1
python3 - <<'PY'
import sqlite3
db = sqlite3.connect("data/oasis.db")
q = ("select e.id, e.ts, e.source_ip, e.attack_type, e.risk, e.action, e.duration_s, x.text "
     "from events e left join explanations x on x.event_id = e.id order by e.id")
for r in db.execute(q):
    print(f"#{r[0]} {r[1]} {r[2]} {r[3]} risk={r[4]} action={r[5]} duration={r[6]}")
    if r[7]:
        print("    ", r[7])
PY
