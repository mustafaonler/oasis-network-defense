#!/usr/bin/env bash
# OASIS scenario: a normal user browses while one attacker escalates and changes IPs.
# Every phase is checked against the event log and the run ends with a PASS/FAIL report.
#
# Run on the Docker host, from anywhere:  bash scripts/scenario.sh
# Needs the lab images (docker compose build). Never starts or stops Docker itself.
# Exit code: 0 all phases passed, 1 a phase failed, 2 Docker not reachable.
set -u
cd "$(dirname "$0")/.." || exit 2
export MSYS_NO_PATHCONV=1   # Git Bash on Windows: keep container paths unchanged

VICTIM=10.10.2.10
SETTLE=8                    # s: one 5 s sensor window plus detector/responder polling
NORMAL_TIME=30              # s of normal browsing before the attack starts
REPORT=()                   # phase|expected|actual|PASS or FAIL
FAILS=0

dc() { docker compose "$@"; }
say() { printf '\n== %s\n' "$*"; }

if ! docker version >/dev/null 2>&1; then
    echo "Docker is not reachable. Start Docker Desktop yourself, then run this again."
    exit 2
fi

# Time from the lab's own clock (the Windows clock can differ from the Docker VM's).
now() { dc exec -T responder python3 -c "import time; print(time.time())"; }
ip_of() { dc exec -T --index "$2" "$1" ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1; }

# Events of one source since an epoch, read-only: "attack_type action duration" per line.
events() {
    dc exec -T responder python3 -c "
import sqlite3, sys
db = sqlite3.connect('file:data/oasis.db?mode=ro', uri=True)
for t, a, d in db.execute('SELECT attack_type, action, duration_s FROM events '
                          'WHERE source_ip=? AND epoch>=? ORDER BY id', (sys.argv[1], float(sys.argv[2]))):
    print(t, a, d or 'manual')" "$1" "$2"
}

record() {   # phase, expected, actual, 1 = pass
    local status=PASS
    if [ "$4" != 1 ]; then status=FAIL; FAILS=$((FAILS + 1)); fi
    REPORT+=("$1|$2|$3|$status")
    echo "   $status: $3"
}

expect_block() {   # phase, ip, attack_type, since
    local got all
    all=$(events "$2" "$4")
    got=$(echo "$all" | awk -v t="$3" '$1 == t && $2 == "block" {print $1 " -> block " $3; exit}')
    if [ -n "$got" ]; then record "$1" "$3 block for $2" "$got" 1
    else record "$1" "$3 block for $2" "${all:-no event}" 0; fi
}

expect_quiet() {   # phase, since, ip...
    local phase=$1 since=$2 all="" ip
    shift 2
    for ip in "$@"; do all+=$(events "$ip" "$since" | sed "s/^/$ip /" | tr '\n' ';'); done
    if [ -z "$all" ]; then record "$phase" "no alert" "no alert" 1
    else record "$phase" "no alert" "$all" 0; fi
}

unblock_all() {
    local ip
    for ip in $(dc exec -T gateway nft list set inet oasis blocklist | grep -oE '10\.[0-9]+\.[0-9]+\.[0-9]+'); do
        dc exec -T responder python3 src/unblock.py "$ip" >/dev/null
    done
}

say "Setup: 4 attacker containers and a normal user"
dc up -d --scale attacker=4 >/dev/null 2>&1 || { echo "docker compose up failed"; exit 2; }
dc --profile scenario up -d user >/dev/null 2>&1 || { echo "user service failed"; exit 2; }
sleep 5
A1=$(ip_of attacker 1); A2=$(ip_of attacker 2); A3=$(ip_of attacker 3); A4=$(ip_of attacker 4)
U=$(ip_of user 1)
echo "attackers: $A1 $A2 $A3 $A4 | user: $U"
unblock_all
sleep "$SETTLE"
T0=$(now)

say "Phase 0: normal browsing for ${NORMAL_TIME}s (user curls the victim every 1-3 s)"
T=$(now); sleep "$NORMAL_TIME"
expect_quiet "0 normal browsing" "$T" "$U" "$A1" "$A2" "$A3" "$A4"

say "Phase 1: attacker ($A1) quick recon, 15 ports"
T=$(now); dc exec -T --index 1 attacker nmap -Pn -sS -p 1-15 "$VICTIM" >/dev/null; sleep "$SETTLE"
expect_quiet "1 recon, 15 ports" "$T" "$A1"

say "Phase 2: attacker ($A1) full scan, 100 ports"
T=$(now); dc exec -T --index 1 attacker nmap -Pn -sS -p 1-100 "$VICTIM" >/dev/null; sleep "$SETTLE"
expect_block "2 port scan" "$A1" port_scan "$T"

say "Phase 3: blocked, the attacker hops to a new IP ($A2) and sends one quiet probe to 3389"
T=$(now); dc exec -T --index 2 attacker hping3 -S -p 3389 -c 1 "$VICTIM" >/dev/null 2>&1; sleep "$SETTLE"
expect_block "3 IP hop, tripwire" "$A2" tripwire "$T"

say "Phase 4: two more IPs ($A3, $A4) split a scan, 10 ports each, no tripwire port"
T=$(now)
dc exec -T --index 3 attacker nmap -Pn -sS -p 30-39 "$VICTIM" >/dev/null &
dc exec -T --index 4 attacker nmap -Pn -sS -p 40-49 "$VICTIM" >/dev/null &
wait; sleep "$SETTLE"
expect_block "4 split scan (a)" "$A3" distributed_scan "$T"
expect_block "4 split scan (b)" "$A4" distributed_scan "$T"

say "Phase 5: the admin unblocks $A1, which starts a SYN flood (3000 SYN)"
dc exec -T responder python3 src/unblock.py "$A1" >/dev/null; sleep 2
T=$(now); dc exec -T --index 1 attacker hping3 -S -p 80 -c 3000 -i u1000 -q "$VICTIM" >/dev/null 2>&1; sleep "$SETTLE"
expect_block "5 SYN flood" "$A1" syn_flood "$T"

say "Throughout: the normal user"
expect_quiet "user never blamed" "$T0" "$U"
code=$(dc exec -T user curl -s -o /dev/null -w '%{http_code}' --max-time 3 "http://$VICTIM/")
if [ "$code" = 200 ]; then record "user can still browse" "HTTP 200" "HTTP $code" 1
else record "user can still browse" "HTTP 200" "HTTP $code" 0; fi

say "LLM agents (information only: blocks never depend on them), waiting 25 s"
sleep 25
dc exec -T responder python3 -c "
import sqlite3, sys
db = sqlite3.connect('file:data/oasis.db?mode=ro', uri=True)
ids = [r[0] for r in db.execute(\"SELECT id FROM events WHERE action='block' AND epoch>=?\", (float(sys.argv[1]),))]
for table in ('explanations', 'analyses'):
    labels = [r[0] or '' for i in ids for r in db.execute('SELECT model FROM %s WHERE event_id=?' % table, (i,))]
    ok = sum('(verified)' in m for m in labels)
    print('%-12s %d block events, %d verified, %d template fallback, %d not yet done'
          % (table, len(ids), ok, len(labels) - ok, len(ids) - len(labels)))" "$T0"

say "Report"
printf '%-24s | %-38s | %-40s | %s\n' "phase" "expected" "actual" "result"
printf '%s\n' "-------------------------+----------------------------------------+------------------------------------------+-------"
for line in "${REPORT[@]}"; do
    IFS='|' read -r p e a s <<<"$line"
    printf '%-24s | %-38s | %-40.40s | %s\n' "$p" "$e" "$a" "$s"
done

say "Cleanup: unblock, stop the user, back to one attacker"
unblock_all
dc --profile scenario stop user >/dev/null 2>&1
dc --profile scenario rm -f user >/dev/null 2>&1
dc up -d --scale attacker=1 >/dev/null 2>&1

if [ "$FAILS" -gt 0 ]; then echo "RESULT: $FAILS check(s) FAILED"; exit 1; fi
echo "RESULT: all checks PASSED"
