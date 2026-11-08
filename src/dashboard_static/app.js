// OASIS dashboard. Read-only: polls /api/state, never sends data.
// Every database string is written with textContent (no HTML parsing), so it stays plain text.
"use strict";

const REFRESH_MS = 5000;
const MAX_ATTACKERS = 5;
const SVG_NS = "http://www.w3.org/2000/svg";

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

let state = null;
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

// ---------- diagram ----------
function node(svg, x, y, w, h, status, title, lines) {
  const g = sv("g");
  g.appendChild(sv("rect", { x, y, width: w, height: h, rx: 8, class: "box" + (status ? " " + status : "") }));
  g.appendChild(sv("text", { x: x + 12, y: y + 20, class: "title" }, title));
  let ty = y + 37;
  for (const [text, cls] of lines) {
    g.appendChild(sv("text", { x: x + 12, y: ty, class: cls || "small" }, text));
    ty += 16;
  }
  svg.appendChild(g);
  return g;
}
function wire(svg, x1, y1, x2, y2, cut) {
  svg.appendChild(sv("path", { d: `M${x1} ${y1} C${(x1 + x2) / 2} ${y1}, ${(x1 + x2) / 2} ${y2}, ${x2} ${y2}`,
    class: "wire" + (cut ? " cut" : "") }));
}
function vwire(svg, x1, y1, x2, y2) {
  svg.appendChild(sv("path", { d: `M${x1} ${y1} C${x1} ${(y1 + y2) / 2}, ${x2} ${(y1 + y2) / 2}, ${x2} ${y2}`, class: "wire" }));
}

function renderDiagram() {
  const svg = document.getElementById("diagram");
  clear(svg);
  const hosts = state.hosts;
  const gw = { x: 350, y: 40, w: 250, h: 130 };
  const vic = { x: 720, y: 70, w: 210, h: 70 };
  const vol = { x: 375, y: 218, w: 200, h: 44 };

  svg.appendChild(sv("text", { x: 230, y: 24, class: "net" }, "attacker-net 10.10.1.0/24"));
  svg.appendChild(sv("text", { x: 610, y: 54, class: "net" }, "victim-net 10.10.2.0/24"));

  // attackers
  let list = hosts.attackers.slice();
  let extra = 0;
  if (list.length > MAX_ATTACKERS) { extra = list.length - (MAX_ATTACKERS - 1); list = list.slice(0, MAX_ATTACKERS - 1); }
  let ay = 34;
  if (!list.length) {
    node(svg, 10, ay, 210, 44, "normal", "attacker", [["son 1 saatte olay yok", "small"]]);
    wire(svg, 220, ay + 22, gw.x, gw.y + 55, false);
  }
  for (const a of list) {
    const st = a.status;
    const ip = a.ip.length > 22 ? a.ip.slice(0, 21) + "…" : a.ip;   // keep it inside the box
    const g = node(svg, 10, ay, 210, 44, st, ip, [[STATUS_TR[st] || st, "st-" + st]]);
    g.childNodes[1].setAttribute("class", "title mono");   // the IP title
    wire(svg, 220, ay + 22, gw.x, gw.y + 55, st === "blocked");
    ay += 52;
  }
  if (extra) {
    node(svg, 10, ay, 210, 36, null, `+${extra} saldırgan daha`, []);
    wire(svg, 220, ay + 18, gw.x, gw.y + 55, false);
  }

  // gateway with the services that share its network namespace
  const active = state.summary.active_blocks;
  node(svg, gw.x, gw.y, gw.w, gw.h, hosts.gateway, "gateway", [
    ["10.10.1.254 · 10.10.2.254", "small mono"],
    [`${STATUS_TR[hosts.gateway]} · aktif engel: ${active}`, "st-" + hosts.gateway],
  ]);
  const chips = [["sensor", "NET_RAW"], ["responder", "NET_ADMIN"]];
  chips.forEach(([name, cap], i) => {
    const cx = gw.x + 12 + i * 118, cy = gw.y + 84;
    svg.appendChild(sv("rect", { x: cx, y: cy, width: 108, height: 36, rx: 6, class: "chip" }));
    svg.appendChild(sv("text", { x: cx + 8, y: cy + 15 }, name));
    svg.appendChild(sv("text", { x: cx + 8, y: cy + 29, class: "small" }, cap));
  });

  // victim
  node(svg, vic.x, vic.y, vic.w, vic.h, hosts.victim, "victim", [
    ["10.10.2.10 · web :80", "small mono"],
    [STATUS_TR[hosts.victim], "st-" + hosts.victim],
  ]);
  wire(svg, gw.x + gw.w, gw.y + 55, vic.x, vic.y + 35, false);

  // shared volume and the services that read it
  vwire(svg, gw.x + gw.w / 2, gw.y + gw.h, vol.x + vol.w / 2, vol.y);
  node(svg, vol.x, vol.y, vol.w, vol.h, null, "oasis-data", [["oasis.db · JSONL", "small"]]);
  const bottom = [
    ["detector", "network: none"],
    ["explainer", "mgmt · LLM (öneri)"],
    ["specialist", "mgmt · LLM (öneri)"],
    ["dashboard", "salt okunur · 127.0.0.1"],
  ];
  bottom.forEach(([name, sub], i) => {
    const bx = 10 + i * 235, by = 310;
    vwire(svg, vol.x + vol.w / 2, vol.y + vol.h, bx + 100, by);
    node(svg, bx, by, 200, 50, null, name, [[sub, "small"]]);
  });
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
