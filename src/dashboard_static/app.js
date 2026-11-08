// OASIS dashboard. Read-only: polls /api/state and listens to /api/live, never sends data.
// Every database string is written with textContent (no HTML parsing), so it stays plain text.
"use strict";

const REFRESH_MS = 5000;
const MAX_ATTACKERS = 5;
const SVG_NS = "http://www.w3.org/2000/svg";

// Live traffic animation. Every dot comes from a measured packet count:
// for each measured second, a source gets as many dots as packets (log scale above 10).
const DOT_POOL = 120;         // hard cap on dots on screen
const DOT_SPEED = 240;        // px per second along the path
const LINEAR_UP_TO = 10;      // pkt/s shown 1:1, above that log scale
const MAX_DOTS_PER_SEC = 30;  // per source
const LIVE_MAX_AGE = 2.5;     // s: a bucket older than this is not animated

const ACTION_TR = {
  block: "engellendi",
  skip_already_blocked: "zaten engelli",
  skip_whitelist: "beyaz liste",
  log_only: "sadece kayıt",
  block_failed: "engelleme başarısız",
  unblock: "engel kaldırıldı",
  unblock_failed: "kaldırma başarısız",
};
const RISK_TR = { low: "düşük", medium: "orta", high: "yüksek" };
const STATUS_TR = { normal: "normal", alarm: "alarm", blocked: "engelli" };

// Diagram geometry (viewBox 0 0 940 380)
const GW = { x: 350, y: 40, w: 250, h: 130 };
const VIC = { x: 720, y: 70, w: 210, h: 70 };
const VOL = { x: 375, y: 218, w: 200, h: 44 };
const LANE_Y = GW.y + 68;     // packets cross the gateway on this line

let state = null;
let live = { ok: false, stale: true, seconds: [] };
let clockOffset = 0;          // server time - browser time, in ms
let selectedId = null;
let countdowns = [];          // [cell, expiresEpoch]
let lastOk = 0;

// ---------- helpers ----------
function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
}
function sv(tag, attrs, text) {
  const e = document.createElementNS(SVG_NS, tag);
  for (const k of Object.keys(attrs || {})) e.setAttribute(k, String(attrs[k]));
  if (text !== undefined && text !== null) e.textContent = String(text);
  return e;
}
function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function nowEpoch() { return (Date.now() + clockOffset) / 1000; }
function fmtTime(epoch) {
  if (epoch === null || epoch === undefined) return "—";
  return new Date(epoch * 1000).toLocaleString("tr-TR", {
    day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}
function fmtDur(s) {
  if (s === null || s === undefined) return "manuel kaldırılana kadar";
  if (s < 3600) return `${Math.round(s / 60)} dk`;
  return `${+(s / 3600).toFixed(1)} sa`;
}
function fmtRemaining(secs) {
  if (secs <= 0) return "süresi doldu";
  secs = Math.floor(secs);
  const h = Math.floor(secs / 3600), m = Math.floor((secs % 3600) / 60), s = secs % 60;
  const mm = String(m).padStart(2, "0"), ss = String(s).padStart(2, "0");
  return h ? `${h}:${mm}:${ss}` : `${m}:${ss}`;
}
function badge(kind, label) {
  // kind comes from the DB: only used as a class when it is a known value
  const known = kind && (kind in ACTION_TR || kind in RISK_TR);
  return el("span", "badge" + (known ? " " + kind : ""), label);
}
function blockLabel(ev) {
  return ev.action === "block" ? fmtDur(ev.duration_s) : "—";
}
function ipKey(ip) {
  const p = String(ip).split(".").map(Number);
  return p.length === 4 && p.every((n) => n >= 0) ? ((p[0] * 256 + p[1]) * 256 + p[2]) * 256 + p[3] : Infinity;
}

// ---------- live data ----------
function latestBucket() {
  if (!live.ok || live.stale || !live.seconds.length) return null;
  const b = live.seconds[live.seconds.length - 1];
  return live.now - b.t <= LIVE_MAX_AGE ? b : null;
}
function liveRate(ip) {
  const b = latestBucket();
  const s = b && b.sources[ip];
  return s ? s : { pkts: 0, syn: 0, ports: 0, fwd: 0 };
}
function liveTotals() {
  const b = latestBucket();
  let pkts = 0, fwd = 0;
  if (b) for (const s of Object.values(b.sources)) { pkts += s.pkts; fwd += s.fwd; }
  return { pkts, fwd };
}
function liveSources() {
  // sources seen in the kept seconds (about 10 s), so a short burst keeps its box a while
  const out = new Set();
  if (live.ok && !live.stale) for (const sec of live.seconds) for (const ip of Object.keys(sec.sources)) out.add(ip);
  return out;
}

// ---------- diagram ----------
let staticLayer = null, dotLayer = null;
let paths = new Map();        // ip -> polyline for its dots
let liveText = new Map();     // ip -> pkt/s text node
let gwLiveText = null, vicLiveText = null;
let diagramKey = "";

function diagramAttackers() {
  const map = new Map();
  for (const a of state.hosts.attackers) map.set(a.ip, a);
  for (const ip of liveSources()) if (!map.has(ip)) map.set(ip, { ip, status: "normal", last_epoch: null });
  const order = { blocked: 0, alarm: 1, normal: 2 };
  return [...map.values()].sort((a, b) => (order[a.status] - order[b.status]) || (ipKey(a.ip) - ipKey(b.ip)));
}

function node(layer, x, y, w, h, status, title, lines) {
  const g = sv("g");
  g.appendChild(sv("rect", { x, y, width: w, height: h, rx: 8, class: "box" + (status ? " " + status : "") }));
  g.appendChild(sv("text", { x: x + 12, y: y + 20, class: "title" }, title));
  let ty = y + 37;
  for (const [text, cls] of lines) {
    g.appendChild(sv("text", { x: x + 12, y: ty, class: cls || "small" }, text));
    ty += 16;
  }
  layer.appendChild(g);
  return g;
}
function curve(x1, y1, x2, y2) {
  const mx = (x1 + x2) / 2;
  return `M${x1} ${y1} C${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}`;
}
function wire(layer, x1, y1, x2, y2, cut) {
  layer.appendChild(sv("path", { d: curve(x1, y1, x2, y2), class: "wire" + (cut ? " cut" : "") }));
}
function vwire(layer, x1, y1, x2, y2) {
  layer.appendChild(sv("path", { d: `M${x1} ${y1} C${x1} ${(y1 + y2) / 2}, ${x2} ${(y1 + y2) / 2}, ${x2} ${y2}`, class: "wire" }));
}
function bezierPoints(x1, y1, x2, y2, n) {
  const mx = (x1 + x2) / 2, pts = [];
  for (let i = 0; i <= n; i++) {
    const t = i / n, u = 1 - t;
    pts.push([u * u * u * x1 + 3 * u * u * t * mx + 3 * u * t * t * mx + t * t * t * x2,
              u * u * u * y1 + 3 * u * u * t * y1 + 3 * u * t * t * y2 + t * t * t * y2]);
  }
  return pts;
}
function makePath(ax, ay) {
  // attacker -> gateway entrance (dots of dropped packets stop here) -> across -> victim
  const pts = bezierPoints(ax, ay, GW.x, LANE_Y, 24);
  pts.push([GW.x + GW.w, LANE_Y], [VIC.x, LANE_Y]);
  const cum = [0];
  for (let i = 1; i < pts.length; i++) cum.push(cum[i - 1] + Math.hypot(pts[i][0] - pts[i - 1][0], pts[i][1] - pts[i - 1][1]));
  return { pts, cum, stop: cum[24] + 6, total: cum[cum.length - 1] };
}
function pointAt(p, d) {
  let i = 1;
  while (i < p.cum.length - 1 && p.cum[i] < d) i++;
  const seg = p.cum[i] - p.cum[i - 1] || 1, f = Math.min(1, Math.max(0, (d - p.cum[i - 1]) / seg));
  return [p.pts[i - 1][0] + (p.pts[i][0] - p.pts[i - 1][0]) * f, p.pts[i - 1][1] + (p.pts[i][1] - p.pts[i - 1][1]) * f];
}

function renderDiagram() {
  if (!state) return;
  const svg = document.getElementById("diagram");
  if (!staticLayer) {
    staticLayer = sv("g");
    dotLayer = sv("g");
    svg.appendChild(staticLayer);
    svg.appendChild(dotLayer);   // dots are drawn above the boxes
    initDots();
  }
  const layer = staticLayer;
  clear(layer);
  paths = new Map();
  liveText = new Map();
  const hosts = state.hosts;

  layer.appendChild(sv("text", { x: 230, y: 24, class: "net" }, "attacker-net 10.10.1.0/24"));
  layer.appendChild(sv("text", { x: 610, y: 54, class: "net" }, "victim-net 10.10.2.0/24"));

  // attackers: recent events or live traffic
  let list = diagramAttackers();
  diagramKey = list.map((a) => a.ip + ":" + a.status).join(",");
  let extra = 0;
  if (list.length > MAX_ATTACKERS) { extra = list.length - (MAX_ATTACKERS - 1); list = list.slice(0, MAX_ATTACKERS - 1); }
  let ay = 34;
  if (!list.length) {
    node(layer, 10, ay, 210, 44, "normal", "attacker", [["son 1 saatte olay veya trafik yok", "small"]]);
    wire(layer, 220, ay + 22, GW.x, LANE_Y, false);
  }
  for (const a of list) {
    const st = a.status;
    const ip = a.ip.length > 22 ? a.ip.slice(0, 21) + "…" : a.ip;   // keep it inside the box
    const g = node(layer, 10, ay, 210, 44, st, ip, [[STATUS_TR[st] || st, "st-" + st]]);
    g.childNodes[1].setAttribute("class", "title mono");   // the IP title
    const t = sv("text", { x: 210, y: ay + 37, "text-anchor": "end", class: "pps" }, "");
    g.appendChild(t);
    liveText.set(a.ip, t);
    wire(layer, 220, ay + 22, GW.x, LANE_Y, st === "blocked");
    paths.set(a.ip, makePath(220, ay + 22));
    ay += 52;
  }
  if (extra) {
    node(layer, 10, ay, 210, 36, null, `+${extra} saldırgan daha`, []);
    wire(layer, 220, ay + 18, GW.x, LANE_Y, false);
  }

  // gateway with the services that share its network namespace
  const active = state.summary.active_blocks;
  node(layer, GW.x, GW.y, GW.w, GW.h, hosts.gateway, "gateway", [
    ["10.10.1.254 · 10.10.2.254", "small mono"],
    [`${STATUS_TR[hosts.gateway]} · aktif engel: ${active}`, "st-" + hosts.gateway],
  ]);
  gwLiveText = sv("text", { x: GW.x + GW.w - 10, y: GW.y + 20, "text-anchor": "end", class: "pps" }, "");
  layer.appendChild(gwLiveText);
  layer.appendChild(sv("path", { d: `M${GW.x} ${LANE_Y} H${GW.x + GW.w}`, class: "wire lane" }));
  const chips = [["sensor", "NET_RAW"], ["responder", "NET_ADMIN"]];
  chips.forEach(([name, cap], i) => {
    const cx = GW.x + 12 + i * 118, cy = GW.y + 84;
    layer.appendChild(sv("rect", { x: cx, y: cy, width: 108, height: 36, rx: 6, class: "chip" }));
    layer.appendChild(sv("text", { x: cx + 8, y: cy + 15 }, name));
    layer.appendChild(sv("text", { x: cx + 8, y: cy + 29, class: "small" }, cap));
  });

  // victim
  node(layer, VIC.x, VIC.y, VIC.w, VIC.h, hosts.victim, "victim", [
    ["10.10.2.10 · web :80", "small mono"],
    [STATUS_TR[hosts.victim], "st-" + hosts.victim],
  ]);
  vicLiveText = sv("text", { x: VIC.x + VIC.w - 10, y: VIC.y + 20, "text-anchor": "end", class: "pps" }, "");
  layer.appendChild(vicLiveText);
  layer.appendChild(sv("path", { d: `M${GW.x + GW.w} ${LANE_Y} H${VIC.x}`, class: "wire" }));

  // shared volume and the services that read it
  vwire(layer, GW.x + GW.w / 2, GW.y + GW.h, VOL.x + VOL.w / 2, VOL.y);
  node(layer, VOL.x, VOL.y, VOL.w, VOL.h, null, "oasis-data", [["oasis.db · JSONL", "small"]]);
  const bottom = [
    ["detector", "network: none"],
    ["explainer", "mgmt · LLM (öneri)"],
    ["specialist", "mgmt · LLM (öneri)"],
    ["dashboard", "salt okunur · 127.0.0.1"],
  ];
  bottom.forEach(([name, sub], i) => {
    const bx = 10 + i * 235, by = 310;
    vwire(layer, VOL.x + VOL.w / 2, VOL.y + VOL.h, bx + 100, by);
    node(layer, bx, by, 200, 50, null, name, [[sub, "small"]]);
  });
  updateLiveTexts();
}

function updateLiveTexts() {
  const fresh = latestBucket() !== null;
  for (const [ip, t] of liveText) {
    const r = liveRate(ip);
    t.textContent = fresh ? `${r.pkts} pkt/s` : "";
  }
  const tot = liveTotals();
  if (gwLiveText) gwLiveText.textContent = fresh ? `gelen ${tot.pkts} · iletilen ${tot.fwd} pkt/s` : "";
  if (vicLiveText) vicLiveText.textContent = fresh ? `gelen ${tot.fwd} pkt/s` : "";
}

// ---------- dots ----------
const dots = [];               // fixed pool, reused
let queues = new Map();        // ip -> {left, interval, next, fwdRatio, i}
let lastBucketT = null;
let animClock = 0, lastFrame = 0;

function initDots() {
  for (let i = 0; i < DOT_POOL; i++) {
    const c = sv("circle", { r: 3.5, cx: -10, cy: -10, class: "pkt", visibility: "hidden" });
    dotLayer.appendChild(c);
    dots.push({ el: c, on: false, path: null, d: 0, fwd: true, fade: 0 });
  }
}
function dotsFor(pkts) {
  if (pkts <= LINEAR_UP_TO) return pkts;
  return Math.min(MAX_DOTS_PER_SEC, Math.round(LINEAR_UP_TO + 8 * Math.log10(pkts / LINEAR_UP_TO)));
}
function onNewBucket(b) {
  // one measured second -> that many dots, spread over the next second
  queues = new Map();
  for (const [ip, s] of Object.entries(b.sources)) {
    const n = dotsFor(s.pkts);
    if (!n) continue;
    const ratio = s.pkts ? Math.min(1, s.fwd / s.pkts) : 0;
    queues.set(ip, { left: n, interval: 1 / n, next: animClock + 0.5 / n, ratio, i: 0 });
  }
}
function spawn(path, fwd) {
  const d = dots.find((x) => !x.on);
  if (!d) return;                // pool full: cap reached, skip
  d.on = true; d.path = path; d.d = 0; d.fwd = fwd; d.fade = 0;
  d.el.setAttribute("class", "pkt");
  d.el.setAttribute("opacity", "1");
  d.el.setAttribute("visibility", "visible");
}
function frame(ts) {
  const dt = lastFrame ? Math.min(0.1, (ts - lastFrame) / 1000) : 0;
  lastFrame = ts;
  animClock += dt;
  for (const [ip, q] of queues) {
    const path = paths.get(ip);
    while (q.left > 0 && q.next <= animClock) {
      // spread forwarded dots evenly by the measured forwarded share
      const fwd = Math.floor((q.i + 1) * q.ratio) > Math.floor(q.i * q.ratio);
      if (path) spawn(path, fwd);
      q.left--; q.i++; q.next += q.interval;
    }
  }
  for (const d of dots) {
    if (!d.on) continue;
    if (d.fade > 0) {
      d.fade -= dt;
      d.el.setAttribute("opacity", Math.max(0, d.fade / 0.5).toFixed(2));
      if (d.fade <= 0) { d.on = false; d.el.setAttribute("visibility", "hidden"); }
      continue;
    }
    d.d += DOT_SPEED * dt;
    if (!d.fwd && d.d >= d.path.stop) {
      d.d = d.path.stop; d.fade = 0.5;           // not forwarded: stops at the gateway
      d.el.setAttribute("class", "pkt drop");
    } else if (d.d >= d.path.total) {
      d.on = false; d.el.setAttribute("visibility", "hidden");
      continue;
    }
    const [x, y] = pointAt(d.path, d.d);
    d.el.setAttribute("cx", x.toFixed(1));
    d.el.setAttribute("cy", y.toFixed(1));
  }
  requestAnimationFrame(frame);
}

function onLive(msg) {
  live = msg;
  const st = document.getElementById("live-status");
  if (!live.ok || live.stale) {
    st.className = "status stale";
    st.textContent = "Canlı akış: sensör verisi yok";
  } else {
    st.className = "status";
    st.textContent = "Canlı akış: bağlı";
  }
  if (!state) return;
  const key = diagramAttackers().map((a) => a.ip + ":" + a.status).join(",");
  if (key !== diagramKey) renderDiagram();
  else updateLiveTexts();
  const b = latestBucket();
  if (b && b.t !== lastBucketT) { lastBucketT = b.t; onNewBucket(b); }
  if (!b) queues = new Map();
}

function startLive() {
  const es = new EventSource("/api/live");
  es.onmessage = (e) => {
    try { onLive(JSON.parse(e.data)); } catch (err) { /* ignore a bad message */ }
  };
  es.onerror = () => {
    const st = document.getElementById("live-status");
    st.className = "status stale";
    st.textContent = "Canlı akış: bağlantı yok, yeniden deneniyor";
    live = { ok: false, stale: true, seconds: [] };
    queues = new Map();
    updateLiveTexts();
  };
}

// ---------- blocked list ----------
function renderBlocked() {
  const tb = document.getElementById("blocked");
  clear(tb);
  countdowns = [];
  if (!state.blocked.length) {
    const tr = el("tr");
    const td = el("td", "empty", "Şu an engelli IP yok.");
    td.colSpan = 5;
    tr.appendChild(td);
    tb.appendChild(tr);
    return;
  }
  for (const b of state.blocked) {
    const tr = el("tr");
    tr.appendChild(el("td", "mono", b.ip));
    tr.appendChild(el("td", null, b.attack_type || "—"));
    tr.appendChild(el("td", "mono", fmtTime(b.since)));
    tr.appendChild(el("td", null, fmtDur(b.duration_s)));
    const rem = el("td", "mono");
    if (b.expires === null) rem.textContent = "manuel kaldırılana kadar";
    else countdowns.push([rem, b.expires]);
    tr.appendChild(rem);
    tb.appendChild(tr);
  }
  tick();
}
function tick() {
  const now = nowEpoch();
  for (const [cell, exp] of countdowns) cell.textContent = fmtRemaining(exp - now);
}

// ---------- events ----------
function renderEvents() {
  const tb = document.getElementById("events");
  clear(tb);
  if (!state.events.length) {
    const tr = el("tr");
    const td = el("td", "empty", "Henüz olay yok.");
    td.colSpan = 7;
    tr.appendChild(td);
    tb.appendChild(tr);
    return;
  }
  for (const ev of state.events) {
    const tr = el("tr");
    tr.tabIndex = 0;
    if (ev.id === selectedId) tr.className = "sel";
    tr.appendChild(el("td", "mono", ev.id));
    tr.appendChild(el("td", "mono", fmtTime(ev.epoch)));
    tr.appendChild(el("td", "mono", ev.source_ip));
    tr.appendChild(el("td", null, ev.attack_type || "—"));
    const risk = el("td");
    risk.appendChild(ev.risk ? badge(ev.risk, RISK_TR[ev.risk] || ev.risk) : el("span", "muted", "—"));
    tr.appendChild(risk);
    const act = el("td");
    act.appendChild(badge(ev.action, ACTION_TR[ev.action] || ev.action));
    if (ev.mode && ev.mode !== "enforce") act.appendChild(el("span", "muted", " (" + ev.mode + ")"));
    tr.appendChild(act);
    tr.appendChild(el("td", null, blockLabel(ev)));
    const pick = () => { selectedId = ev.id; renderEvents(); renderDetail(); };
    tr.addEventListener("click", pick);
    tr.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); pick(); } });
    tb.appendChild(tr);
  }
}

function addFact(dl, key, value) {
  dl.appendChild(el("dt", null, key));
  dl.appendChild(el("dd", null, value === null || value === undefined || value === "" ? "—" : value));
}

function renderDetail() {
  const box = document.getElementById("detail");
  clear(box);
  const ev = state && state.events.find((e) => e.id === selectedId);
  if (!ev) { box.appendChild(el("p", "muted", "Bir olay seçin.")); return; }

  box.appendChild(el("h3", null, `#${ev.id} · ${ev.source_ip} · ${ev.attack_type || ACTION_TR[ev.action] || ev.action}`));
  const dl = el("dl");
  addFact(dl, "Zaman", fmtTime(ev.epoch));
  addFact(dl, "Risk", ev.risk ? (RISK_TR[ev.risk] || ev.risk) : null);
  addFact(dl, "Aksiyon", ACTION_TR[ev.action] || ev.action);
  addFact(dl, "Engel süresi", blockLabel(ev));
  addFact(dl, "Mod", ev.mode);
  addFact(dl, "Kural gerekçesi", ev.reason);
  box.appendChild(dl);

  // explainer
  box.appendChild(el("h4", null, "Explainer açıklaması"));
  if (ev.explanation) {
    box.appendChild(el("p", "text", ev.explanation.text));
    box.appendChild(el("p", "model", ev.explanation.model));
  } else {
    box.appendChild(el("p", "muted", ev.action === "block"
      ? "Açıklama henüz üretilmedi." : "Explainer sadece engelleme olaylarını açıklar."));
  }

  // specialist
  box.appendChild(el("h4", null, "Specialist görüşü"));
  const an = ev.analysis;
  if (an) {
    const d2 = el("dl");
    addFact(d2, "Ajan", an.agent);
    addFact(d2, "Görüş", an.verdict);
    addFact(d2, "Güven", an.confidence);
    addFact(d2, "Risk önerisi", an.risk_opinion);
    box.appendChild(d2);
    if (an.reasons.length) {
      const ul = el("ul");
      for (const r of an.reasons) ul.appendChild(el("li", null, r));
      box.appendChild(ul);
    }
    box.appendChild(el("p", "model", an.model));
  } else {
    box.appendChild(el("p", "muted", ev.action === "block"
      ? "Görüş henüz üretilmedi." : "Specialist sadece engelleme olaylarını değerlendirir."));
  }

  // evidence (sensor window), shown as plain key: value text
  if (ev.evidence && typeof ev.evidence === "object") {
    box.appendChild(el("h4", null, "Kanıt (sensör penceresi)"));
    const lines = Object.entries(ev.evidence).map(([k, v]) =>
      `${k}: ${v !== null && typeof v === "object" ? JSON.stringify(v) : String(v)}`);
    box.appendChild(el("pre", null, lines.join("\n")));
  }
}

// ---------- main loop ----------
function render() {
  document.getElementById("c-active").textContent = state.summary.active_blocks;
  document.getElementById("c-hour").textContent = state.summary.blocks_last_hour;
  document.getElementById("c-total").textContent = state.summary.total_events;
  document.getElementById("alarm-min").textContent = Math.round(state.limits.alarm_window_s / 60);
  const err = document.getElementById("error");
  err.hidden = state.ok;
  err.textContent = state.ok ? "" : state.error;
  renderDiagram();
  renderBlocked();
  renderEvents();
  renderDetail();
}

async function refresh() {
  const status = document.getElementById("status");
  try {
    const r = await fetch("/api/state", { cache: "no-store", credentials: "same-origin" });
    if (!r.ok) throw new Error("HTTP " + r.status);
    state = await r.json();
    clockOffset = state.now * 1000 - Date.now();
    lastOk = Date.now();
    render();
    status.className = "status";
    status.textContent = "Son güncelleme: " + new Date().toLocaleTimeString("tr-TR") + " · her 5 sn";
  } catch (e) {
    status.className = "status stale";
    status.textContent = "Sunucuya ulaşılamadı" + (lastOk ? " · son veri " + new Date(lastOk).toLocaleTimeString("tr-TR") : "");
  }
}

refresh();
setInterval(refresh, REFRESH_MS);
setInterval(tick, 1000);
startLive();
requestAnimationFrame(frame);
