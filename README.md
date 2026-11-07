# OASIS — LLM and Multi-Agent Network Defense

> **Warning: for isolated lab use only.** OASIS generates attack traffic (port scans,
> SYN floods) and changes firewall rules. Run it only in the Docker lab described here
> or in a lab VM you control. Never point the attacker tools at networks or hosts you
> do not own or have explicit permission to test.

OASIS is a graduation project: a small network defense system that watches traffic,
detects attacks with rules, blocks the attacker with nftables, and then asks LLM agents
to explain the decision and give a second opinion.

This branch (`docker`) moves the project from a set of VMs into Docker containers.
The working VM version stays on `main` and is tagged **`demo-v2`**.

## Core principle

- **Blocking decisions are made by rules, not by the LLM.** The detector and the
  responder are plain code with fixed thresholds and a fixed action ladder. The LLM
  agents are advisory only: they never touch the firewall and never change the risk level.
- **Only numeric fields are sent to the LLM.** Agents get packet counts, rates,
  thresholds and a few fixed enum values (`port_scan`, `medium`, `block`, ...).
  No IP addresses and no free text from traffic or alerts are sent.
- **LLM output is checked.** Every number in an LLM answer must appear in the evidence;
  otherwise the answer is rejected and a rule-based template is stored instead.

## Architecture

### Pipeline

```
 sensor ──windows.jsonl──> detector ──alerts.jsonl──> responder ──oasis.db──> explainer
 (scapy, 5 s windows)      (rules)                    (nftables)        └───> specialist
```

| Component | Role | Talks to the LLM? | Touches the firewall? |
|---|---|---|---|
| `sensor.py` | Sniffs the gateway's attacker-side interface, writes per-source 5-second summaries | No | No |
| `detector.py` | Rules: ≥ 20 distinct SYN ports in a window → `port_scan`; ≥ 50 SYN/s → `syn_flood` | No | No |
| `responder.py` | Whitelist → risk level → action ladder → nftables blocklist → SQLite event log | No | **Yes** |
| `explainer.py` | Explains each block in Turkish (3–4 sentences), number-verified | Yes (numbers only) | No |
| `specialist.py` | Router picks `PortScanAgent` or `SynFloodAgent` for a second opinion (JSON) | Yes (numbers only) | No |
| `unblock.py` | Manual unblock, logged to the event table | No | **Yes** |
| `policy.py` | Action ladder constants and the repeat count, shared by the responder and the agents (no firewall code) | No | No |

**Block duration ladder** (`responder.py`): `LADDER = [5 min, 30 min, until manual unblock]`.
The start step comes from the risk level (`port_scan` = medium → step 0,
`syn_flood` = high → step 1). Each earlier block of the same IP in the last hour moves it
one step up. Unblocking does not reset that count.

### Docker network layout

```
                 attacker-net 10.10.1.0/24             victim-net 10.10.2.0/24
 ┌───────────┐   (no NAT, auto IPs .64-.127)   ┌─────────┐   (no NAT)   ┌──────────┐
 │ attacker  │──────────────────────────────── │ gateway │──────────────│  victim  │
 │ (scalable)│   default route → .1.254        │ .1.254  │  .2.254      │ .2.10    │
 └───────────┘                                 │ .2.254  │              │ web :80  │
                                               └────┬────┘              └──────────┘
                              shares the gateway's  │ network namespace
                                      ┌─────────────┴────────────┐
                                      │  sensor (NET_RAW)        │
                                      │  responder (NET_ADMIN)   │
                                      └──────────────────────────┘
   detector: network_mode none         oasis-data volume: windows.jsonl, alerts.jsonl, oasis.db
                                       (shared by sensor, detector, responder, explainer, specialist)
                 mgmt 10.10.9.0/24 (NAT on — the only network with internet access)
              ┌────────────┐ ┌────────────┐
              │ explainer  │ │ specialist │ ──> LLM API (Gemini or Anthropic)
              └────────────┘ └────────────┘
```

How the lab is kept offline and isolated:

- Lab networks have **no NAT** (`enable_ip_masquerade: false`).
- The gateway **removes its default route** and loads a separate nftables table,
  `inet lab_isolation`, that only forwards traffic between the two lab subnets.
  The OASIS blocklist lives in its own table, `inet oasis`, so the responder never touches
  the isolation rule.
- Lab containers use the gateway as their **DNS upstream**, and no DNS server runs there.
  External names do not resolve, which closes a DNS tunnel path through Docker's
  embedded DNS. Names on shared networks (for example `gateway`) still resolve.
- The lab networks are **not** `internal: true`, on purpose: Docker then drops routed
  traffic between the two subnets, so the gateway could not route at all.

Least privilege: every OASIS service starts with `cap_drop: [ALL]`. Only the sensor gets
`NET_RAW` and only the responder gets `NET_ADMIN`. The detector has no network at all.
`.env`, `data/` and `.git` are excluded from images by `.dockerignore`.

## Setup and usage

Requirements: Docker with Compose v2.24 or newer (tested on Docker Desktop 29.7 for Windows).

```bash
git clone https://github.com/mustafaonler/oasis-network-defense.git
cd oasis-network-defense
git switch docker
```

### API key (optional)

Without a key, the explainer and specialist fall back to rule-based templates, and
everything else works the same.

```bash
cp .env.example .env
```

Open `.env` in an editor and fill in **one** provider key (`GEMINI_API_KEY` or
`ANTHROPIC_API_KEY`). `.env` is ignored by git and never copied into an image.
`OASIS_MODEL` can override the model. With Gemini, `OASIS_MODEL=gemini-3.5-flash-lite`
was tested and is recommended, because the code default `gemini-2.5-flash` is deprecated.
Leave that line commented out unless you set a value, because an empty `OASIS_MODEL=`
makes every LLM call fail.

### Start

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f sensor detector responder explainer specialist
```

After you create or change `.env`, recreate the agents so they pick it up:

```bash
docker compose up -d --force-recreate explainer specialist
```

### Example tests

```bash
# attacker's current IP (no fixed IP, it comes from 10.10.1.64/26)
docker compose exec attacker ip -4 -br addr show eth0

# normal traffic: no alert
docker compose exec attacker curl -s http://10.10.2.10/

# small scan below the threshold: no alert
docker compose exec attacker nmap -Pn -sS -p 1-15 10.10.2.10

# port scan: port_scan alert -> block
docker compose exec attacker nmap -Pn -sS -p 1-30 10.10.2.10

# limited SYN flood (5000 packets, not --flood): syn_flood alert -> block
docker compose exec attacker hping3 -S -p 80 -c 5000 -i u1000 -q 10.10.2.10

# see the blocklist and remove a block
docker compose exec gateway nft list set inet oasis blocklist
docker compose exec responder python3 src/unblock.py <attacker-ip>

# watch traffic pass through the gateway
docker compose exec gateway tcpdump -ni any icmp

# several attackers: start three, run a command in the second one, go back to one
docker compose up -d --scale attacker=3
docker compose exec --index 2 attacker nmap -Pn -sS -p 1-30 10.10.2.10
docker compose up -d --scale attacker=1
```

Stop the lab with `docker compose down`. To also delete the event database, add `-v`.

## Test results

All tests were run manually on Docker Desktop (Windows). Each test was compared with an
expected result written down before it ran.

### Stage A — gateway, attacker, victim

| # | Test | Result |
|---|---|---|
| 1 | `compose up`: 2 networks, 3 containers | Pass |
| 2 | Gateway finds its interfaces by IP; nft tables loaded | Pass |
| 3 | Fixed IPs (.1.254, .2.254, .2.10); attacker IP from `ip_range`; gateway has no default route | Pass |
| 4 | Ping attacker → victim; tcpdump shows every packet crossing `eth0 ↔ eth1` on the gateway | Pass |
| 5 | No internet from attacker, victim or gateway (ICMP and TCP) | Pass |
| 6 | Bypass attempt (attacker route via the Docker host bridge) fails | Pass |
| 7 | Adding the attacker to the blocklist drops its traffic | Pass |
| 8 | Removing it restores traffic | Pass |
| 9 | External DNS names do not resolve; `gateway` still resolves | Pass |

### Stage B — sensor, detector, responder

| # | Test | Result |
|---|---|---|
| B1 | All services up; sensor finds its interface itself; gateway DNS closed | Pass |
| B2 | Without `OASIS_*` variables the code keeps the exact VM values (no regression on `main`) | Pass |
| B3 | Normal traffic and a 15-port scan: no alert; 30-port scan: `port_scan`, block 5 min | Pass |
| B4 | 100-port scan by the same IP: block **30 min** (repeat escalation) | Pass |
| B5 | `unblock.py` restores traffic and logs an `unblock` event | Pass |
| B6 | 5000 SYN (~890 SYN/s): `syn_flood`, block **until manual unblock** (high risk + two earlier blocks) | Pass |

### Stage C — explainer, specialist

| # | Test | Result |
|---|---|---|
| C1 | Both agents up on the mgmt network, no restarts | Pass |
| C2 | No key variables inside the containers when `.env` is absent | Pass |
| C3 | Without a key: `[mock]` explanations and `[rules]` opinions for all block events | Pass |
| C4 | From the explainer: ping and TCP to victim and attacker fail; mgmt and internet pings work | Pass |
| C5 | LLM payloads for real events contain no IP address and no free text | Pass |
| C6 | Real LLM call with a Gemini key: both agents labelled `gemini:gemini-2.5-flash (verified)` | Pass |
| C6b | Same test with `OASIS_MODEL=gemini-3.5-flash-lite`: both agents labelled `gemini:gemini-3.5-flash-lite (verified)` | Pass |

C6 first failed: google-genai 3.x uses the `v1` API by default, and there
`gemini-2.5-flash` rejects `system_instruction` (HTTP 400). Both agents fell back to
templates as designed. The fix sets `api_version="v1beta"` on the Gemini client.

### Fix: repeat count in the LLM payload

| # | Test | Result |
|---|---|---|
| F1-R | Responder dry-run scenario (repeats, expiry, whitelist, unknown type, bad IP): same DB rows and output as `main` (VM env) and as the previous commit (VM and Docker env) | Pass |
| F1-A | Agents do not load `responder.py`; `policy.py` imports nothing | Pass |
| P1 | For every stored block, the computed ladder step matches the duration the responder applied | Pass |
| P2 | Template explanations give the repeat count as the reason | Pass |
| P3 | Same new IP blocked twice: 5 min (start step), then 30 min with "1 prior block" as the reason; both agents `(verified)` | Pass |
| P4 | New payloads contain no IP address and no free text | Pass |

### Fix: DNS lookups not counted as scan targets

| # | Test | Result |
|---|---|---|
| R1 | VM settings (no `OASIS_*`): BPF, interface and statistics for the same in-memory packets are identical to `main` | Pass |
| R2 | Docker settings, in-memory packets: a DNS lookup to the gateway is no longer a target; a SYN to the gateway's port 22 still is; DNS to another server still is; packet counts unchanged | Pass |
| R3 | Live 30-port scan: `unique_dst_ips` is 1 (was 2), `port_scan` alert as before | Pass |

### Stage D — several attackers (`--scale attacker=3`)

| # | Test | Result |
|---|---|---|
| D1 | Three attackers get distinct IPs from `10.10.1.64/26`; route and DNS point at the gateway | Pass |
| D2 | A ping from each attacker crosses the gateway (three source IPs in tcpdump) | Pass |
| D3 | Simultaneous 30-port scans: three windows, three `port_scan` alerts, three blocks; durations follow each IP's own history | Pass |
| D4 | Unblocking one attacker restores only that attacker; the other two stay blocked | Pass |
| D5 | Distributed scan (10 ports per attacker, 30 in total): no alert, as expected for per-source rules (see limitations) | Pass |
| D6 | The agents handled all three events: six verified LLM results, no rate-limit errors | Pass |
| D7 | Blocklist empty, back to one attacker | Pass |

## Known limitations

- **Simple detection.** There are two rules with fixed thresholds over 5-second windows.
  A slow scan (fewer than 20 new ports per window) is not detected. A scan that straddles
  two windows can stay under the threshold in both.
- **Per-source rules miss distributed scans.** Each source IP is judged on its own. Three
  attackers that each probe 10 ports (30 in total) raise no alert, because none of them
  reaches the 20-port threshold (Stage D, test D5).
- **Recycled lab IPs keep their history.** Docker hands a freed address to the next
  attacker container, so a new container can inherit an old IP's recent blocks and get a
  longer block on its first scan.
- **Only two attack types** (port scan, SYN flood). There is no detection for UDP floods,
  application-layer attacks, brute force and similar attacks.
- **One direction only.** The sensor watches traffic from `attacker-net`. Traffic that
  starts on the victim side is not analyzed. The lab is IPv4 only; IPv6 is dropped.
- **Small blind spot from the DNS fix.** In the Docker lab, packets to the gateway on
  port 53 (UDP or TCP) are not counted in `unique_dst_ips`, because that is the lab's DNS
  server address. A probe of the gateway's port 53 therefore does not add the gateway as a
  target. It is still counted in `packet_count`, and a TCP SYN to port 53 still counts as a
  probed port. Probes of the gateway's other ports are counted as usual. The VM version
  is unchanged (`OASIS_SENSOR_DNS_SERVER` unset).
- **Spoofing.** A SYN flood with spoofed source addresses could make the responder block
  innocent addresses. The whitelist protects only the lab infrastructure.
- **File-based messaging.** Components exchange data through JSONL files and one SQLite
  database on a shared volume. This is simple and transparent but single-host and not
  built for high traffic.
- **Containers run as root** (with capabilities dropped). The attacker container keeps
  `NET_ADMIN` so it can set its route. Bypassing the gateway was tested and blocked, but
  lab isolation relies on Docker's own isolation rules as well as OASIS's.
- **Secrets are environment variables.** Anyone who can run `docker inspect` on the agent
  containers can read the key.
- **LLM dependence.** Explanations are advisory and may be generic. Provider outages
  (such as HTTP 503) fall back to templates. `gemini-2.5-flash`, the code's default Gemini
  model, is deprecated by Google (earliest shutdown 1 December 2026). Set `OASIS_MODEL`
  to a current model. `OASIS_MODEL` is shared by both providers, so change or remove it
  when switching providers.
- **LLM explanations can be wrong even when every number checks out.** The number check
  catches invented numbers, not wrong reasoning. Seen in testing:
  - Before the repeat count was added to the payload, the explainer said a 30-minute
    block was due to "medium risk" when the real cause was repeat escalation. The payload
    now carries `repeat_rule`, and the explanations give the right reason. They sometimes
    quote raw field names such as `start_step_for_risk` in the Turkish text.
  - `unique_dst_ips` used to count nmap's reverse-DNS query to the gateway, and the
    specialist read it as a second scan target. Fixed: the sensor no longer counts DNS
    lookups to the lab DNS server as targets (see the blind spot below).
  - The specialist suggested `raise` for a 30-port scan against a threshold of 20.
    Opinions are advisory and never change the risk level.
  - With `gemini-3.5-flash-lite` the specialist attached real numbers to the wrong fields
    ("30 SYN out of 30.0 packets" when there were 33 packets). The check only asks whether
    a number appears in the payload, not which field it belongs to.
- **No automated test suite.** The tests above are manual command sequences.
- **Tested only on Docker Desktop for Windows.** Other Docker hosts may behave differently.

## Status

### Done

- Stage A: Docker lab with gateway, attacker and victim, routing through the gateway,
  nftables blocklist, lab isolation, DNS leak closed
- Stage B: sensor, detector and responder as separate least-privilege services; VM
  defaults kept through `OASIS_*` variables
- Stage C (C1–C6): explainer and specialist on an isolated mgmt network, keys only from
  `.env` at runtime, template fallback without a key, numeric-only LLM payloads, real
  Gemini calls verified with `gemini-2.5-flash` and `gemini-3.5-flash-lite`
- Repeat count and ladder step in the LLM payload (`repeat_rule`, from the shared
  `policy.py`): explanations now give the real reason for a block duration. The responder's
  behaviour is unchanged (dry-run regression against `main` and the previous commit).
- Sensor ignores DNS lookups to the lab DNS server when counting targets
  (`OASIS_SENSOR_DNS_SERVER`); VM behaviour unchanged.
- Stage D: three attackers at once (`--scale attacker=3`), each detected, blocked and
  unblocked independently

### Planned

- Update the default Gemini model before the `gemini-2.5-flash` shutdown
- Detection across sources (distributed scans), for example per-target port counts
- Automated tests for the detection rules and the action ladder
- Further README and documentation edits

## AI assistance

Claude (Anthropic) was used as a development assistant for this Docker migration: writing
code and configuration, and running the test commands. The design decisions,
requirements, test plans and the review of every result were done by me.
