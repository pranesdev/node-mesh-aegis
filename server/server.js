// server.js — AEGIS Networking simulator.
//
// Models the real PMA* cost function per overview.md §11:
//   rssi   = α·rssiCost + β·etxCost + γ·batteryCost + δ·hopCost + ε·riskCost
//   mode 'RSSI': only rssi/hop; mode 'RSSI+ETX' adds ETX-derived cost.
// The server is dumb: emits topology + per-edge RSSI/ETX/battery/risk,
// client computes the actual route and decides. We also include:
//   - EWMA RSSI prediction (α=0.2) + 3-sample slope buffer + monotonic guard
//     → risk bit if forecast RSSI < THRESHOLD_HARD and 3 consecutive declines
//   - Welford online delivery-ratio (ETX) per edge
//   - Battery drain per hop (0.05% per packet forwarded)
//   - Anomaly bit if delivery ratio drifts > 3σ below mean

import express from 'express';
import { WebSocketServer } from 'ws';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(__dirname, '..');

const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, cur, i, arr) => {
    if (cur.startsWith('--')) acc.push([cur.slice(2), arr[i + 1]]);
    return acc;
  }, [])
);
const HTTP_PORT = parseInt(args['port-http'] || process.env.PORT || '4000', 10);
const TICK_MS = parseInt(args['tick'] || '1200', 10);   // slow down per request

const CLIENTS = new Set();

// ===== Tunables (mirror mesh_node.ino config.h) =====
const ALPHA_EWMA = 0.2;
const PRED_SLOPE_THRESH = -0.03;
const PRED_TREND_COUNT = 3;
const THRESHOLD_HARD = -70;     // dBm
const PRED_WINDOW_S = 5;

const NODE_ROLES = [2, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

let state = { nodeCount: 16, noise: 2 };

// ===== Topology =====
let nodes = [];
let edges = [];                 // { a, b, rssiEma, slopeBuf, history, pEma, mu, var, battery }
let srcRotate = 1;
let pinnedSrc = null;           // when set, src stays on this node every tick
let tickN = 0;

function dist(a, b) { return Math.hypot(a.x - b.x, a.y - b.y); }
function edgeKey(a, b) { return a < b ? `${a}-${b}` : `${b}-${a}`; }

const SIM_W = 1100;
const SIM_H = 420;

// Pathological-but-deterministic initial seed so the page renders without chaos.
function regen(n) {
  state.nodeCount = n;
  nodes = [];
  nodes.push({ id: 0, x: SIM_W * 0.10, y: SIM_H * 0.5, isGateway: true, role: NODE_ROLES[0] });
  let s = n * 12345 + 7;
  for (let i = 1; i < n; i++) {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    const x = SIM_W * 0.22 + (s % (SIM_W * 0.72));
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    const y = 30 + (s % (SIM_H - 60));
    nodes.push({
      id: i, x, y, isGateway: false, role: NODE_ROLES[i % NODE_ROLES.length],
      battery: 100 - (i * 5) % 60, anomaly: false, route_mode: 1,
      vx: (Math.random() - 0.5) * 2, vy: (Math.random() - 0.5) * 2
    });
  }
  edges = [];
  for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) {
    const d0 = dist(nodes[i], nodes[j]);
    const rssi0 = Math.round(-30 - 55 * (d0 / 190) + (Math.random() - 0.5) * state.noise);
    edges.push({
      a: Math.min(i, j), b: Math.max(i, j),
      rssi: rssi0,            // last raw sample
      rssiEma: rssi0,         // EWMA
      slopeBuf: [],           // last 3 slopes
      prevRssi: rssi0,
      mu: 0.9,                // Welford mean of p (= delivery prob)
      M2: 0,
      samples: 0,
      pEma: 0.9,              // EWMA of p
      risk: 0,                // 0 or 1: forecast breach
      interfered: false,
      lastForecast: rssi0,
      history: [rssi0],
    });
  }
  srcRotate = 1;
  pinnedSrc = null;          // any pin resets on topology regeneration
  tickN = 0;
}

function setInterfered(key, on) {
  const [i, j] = key.split('-').map(Number);
  const e = edges.find((ee) => ee.a === i && ee.b === j || ee.a === j && ee.b === i);
  if (e) e.interfered = !!on;
}

// ===== Per-tick update =====
function tickTopology() {
  tickN++;
  // Battery drain and node mobility
  for (const n of nodes) {
    if (!n.isGateway) {
      n.battery = Math.max(0, n.battery - 0.05 + (Math.random() - 0.5) * 0.04);
      if (n.battery > 0) {
        n.vx += (Math.random() - 0.5) * 0.5;
        n.vy += (Math.random() - 0.5) * 0.5;
        n.vx *= 0.95; n.vy *= 0.95; // drag
        n.x += n.vx; n.y += n.vy;
        if (n.x < 20) { n.x = 20; n.vx *= -1; } else if (n.x > SIM_W - 20) { n.x = SIM_W - 20; n.vx *= -1; }
        if (n.y < 20) { n.y = 20; n.vy *= -1; } else if (n.y > SIM_H - 20) { n.y = SIM_H - 20; n.vy *= -1; }
      }
    }
  }
  // Per-edge: resample RSSI, update EWMA + slope, update Welford delivery prob.
  for (const e of edges) {
    const n = nodes.find((x) => x.id === e.a);
    const m = nodes.find((x) => x.id === e.b);
    
    // Environmental wave interference (1% chance to start, lasts a few ticks)
    if (Math.random() < 0.01 && !e.interfered) e.waveDuration = 5 + Math.random() * 10;
    if (e.waveDuration > 0) e.waveDuration--;

    const d = dist(n, m);
    // RSSI = -30 − 55·(d/190) + jitter·noise − 22 if interfered
    let r = -30 - 55 * (d / 190) + (Math.random() - 0.5) * 2 * state.noise;
    if (e.interfered) r -= 22;
    if (e.waveDuration > 0) r -= 25; // wave attenuation
    
    // Dead nodes sever all connections
    if (n.battery === 0 || m.battery === 0) r = -120;

    const rssi = Math.round(r);

    // Update EWMA
    e.rssiEma = ALPHA_EWMA * rssi + (1 - ALPHA_EWMA) * e.rssiEma;
    // Update slope buffer (Δ/Δt in dBm/s; ~1 tick ≈ TICK_MS)
    const slope = (rssi - e.prevRssi) / (TICK_MS / 1000);
    e.slopeBuf.push(slope); if (e.slopeBuf.length > PRED_TREND_COUNT) e.slopeBuf.shift();
    e.prevRssi = rssi;
    // Forecast: m + slope·W; if forecast < THRESHOLD_HARD AND last 3 slopes all < thresh → risk bit
    const meanSlope = e.slopeBuf.reduce((a, b) => a + b, 0) / Math.max(1, e.slopeBuf.length);
    const forecast = e.rssiEma + meanSlope * PRED_WINDOW_S;
    e.lastForecast = forecast;
    const allDeclining = e.slopeBuf.length === PRED_TREND_COUNT &&
      e.slopeBuf.every((s) => s < PRED_SLOPE_THRESH);
    e.risk = (forecast < THRESHOLD_HARD && allDeclining) ? 1 : 0;

    // Delivery probability (Welford + EMA)
    const ok = Math.random() < ((e.interfered ? 0.35 : 1) * Math.min(0.99, Math.max(0.05,
      (forecast + 100) / 80,  // map -100..-20 → 0..1, capped
    )));
    e.samples++;
    const delta = (ok ? 1 : 0) - e.mu;
    e.mu += delta / e.samples;
    e.M2 += delta * ((ok ? 1 : 0) - e.mu);
    e.pEma = 0.7 * e.pEma + 0.3 * (ok ? 1 : 0);

    e.rssi = rssi;
    e.history.push(rssi); if (e.history.length > 10) e.history.shift();
    e.label = `${rssi}dBm` + (e.risk ? ` ⚠` : ``);
  }
  // Anomaly on a node: roughly 5% of nodes if delivery on any of its edges falls >3σ below mean
  for (const n of nodes) {
    n.anomaly = false;
    for (const e of edges) {
      if (e.a !== n.id && e.b !== n.id) continue;
      if (e.samples < 8) continue;
      const sigma = Math.sqrt(e.M2 / e.samples);
      if (sigma > 0.05 && e.pEma < e.mu - 3 * sigma) { n.anomaly = true; break; }
    }
  }
}

function snapshot(srcOverride) {
  tickTopology();
  if (srcOverride !== undefined) {
    // explicit pick_src from a client: pin
    srcRotate = srcOverride;
    pinnedSrc = srcOverride;
  } else if (pinnedSrc === null) {
    // auto-rotate only when no client has pinned a source
    srcRotate = (srcRotate % Math.max(1, nodes.length - 1)) + 1;
  } else {
    // honour the existing pin
    srcRotate = pinnedSrc;
  }
  const src = nodes[srcRotate] || nodes[Math.max(1, srcRotate % (nodes.length - 1) + 1)];
  return {
    cmd: 'tick',
    tick: tickN,
    nodes: nodes.map((n) => ({ ...n, history: undefined })),
    edges: edges.map((e) => ({
      a: e.a, b: e.b,
      rssi: e.rssi, rssiEma: Math.round(e.rssiEma), forecast: Math.round(e.lastForecast),
      pEma: e.pEma, risk: e.risk, interfered: e.interfered, history: e.history, label: e.label,
    })),
    src: src?.id ?? 0,
    target: 0,                // GW always
    tickMs: TICK_MS,
    pinned: pinnedSrc !== null,
  };
}

regen(state.nodeCount);

// ===== HTTP + WS =====
const app = express();
app.use(express.static(ROOT));  // serves /positions.json etc.

// ---- ESP32 ingest ---------------------------------------------------------
// The gateway firmware batches one JSON record per second into a 5 s POST.
// Body can be a single JSON object OR newline-delimited JSON (NDJSON).
// Each line is wrapped into a {cmd:'telemetry', line: <json>} envelope and
// re-broadcast over WebSocket so the dashboard can overlay real-node data
// on top of the simulator.
app.use('/ingest', express.text({ type: '*/*', limit: '256kb' }));
app.post('/ingest', (req, res) => {
    const body = (req.body || '').toString();
    let n = 0;
    if (body.trim().startsWith('{')) {
        // single record or NDJSON — split on newlines just in case
        for (const line of body.split(/\r?\n/)) {
            const t = line.trim();
            if (!t.startsWith('{')) continue;
            let rec;
            try { rec = JSON.parse(t); } catch { continue; }      // drop malformed
            // cache latest record per node so the next snapshot can merge it in
            if (typeof rec.node === 'number') liveNodes[rec.node] = rec;
            broadcast({ cmd: 'telemetry', line: t });
            n++;
        }
    }
    console.log(`[ingest] ${n} record(s) from ${req.ip}`);
    res.status(200).json({ ok: true, count: n });
});

const httpServer = createServer(app);
const wss = new WebSocketServer({ server: httpServer, path: '/ws' });

wss.on('connection', (ws) => {
  CLIENTS.add(ws);
  try { ws.send(JSON.stringify(withLive(snapshot()))); } catch {}
  ws.on('message', (raw) => {
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }
    switch (msg.cmd) {
      case 'new_topology': regen(state.nodeCount); broadcast(snapshot()); break;
      case 'set_nodes':    regen(Math.max(6, Math.min(40, msg.n | 0))); broadcast(snapshot()); break;
      case 'set_noise':    state.noise = Math.max(0, Math.min(10, msg.n | 0)); broadcast(snapshot()); break;
      case 'reset_stats':  regen(state.nodeCount); broadcast(snapshot()); break;
      case 'toggle_edge':  setInterfered(msg.key, !!msg.on); broadcast(snapshot()); break;
      case 'set_mode':     broadcast({ cmd: 'mode', mode: msg.mode }); break;
      case 'pick_src':
        if (msg.src === null || msg.src === undefined || msg.src === '') {
          pinnedSrc = null;           // resume auto-rotate
          broadcast(snapshot());
        } else {
          broadcast(snapshot(msg.src | 0));    // pin and emit
        }
        break;
      case 'recharge':
        for (const n of nodes) n.battery = 100;
        broadcast(snapshot());
        break;
    }
  });
  ws.on('close', () => CLIENTS.delete(ws));
});

// Live ESP32 records keyed by node id — populated by POST /ingest and
// folded into the next broadcast by `withLive()`.
const liveNodes = {};
function withLive(snap) {
    const ids = Object.keys(liveNodes);
    if (!ids.length) return snap;
    // convert live ESP32 records into the {nodes:[…]} shape the dashboard
    // already understands.  Live records replace any simulator node with
    // the same id, so a real gateway (id=0) overlays the simulated one.
    const live = ids.map((k) => {
        const r = liveNodes[k];
        const id = +k;
        return {
            id,
            role: r.role ?? 2,
            battery: r.bat ?? 100,
            anomaly: false,
            route_mode: r.mode ?? 0,
            rssi: r.rssi ?? -60,
            neighbors: (r.nbrs || []).map((n) => ({
                id: n.id, rssi: n.rssi, etx: Math.round((n.etx || 1) * 100),
                battery: n.bat, risk: n.risk, hop: n.hop,
            })),
        };
    });
    // merge: live first, then any simulator nodes not in live
    const liveIds = new Set(live.map((n) => n.id));
    const simOnly = (snap.nodes || []).filter((n) => !liveIds.has(n.id));
    return { ...snap, nodes: [...live, ...simOnly] };
}

function broadcast(obj) {
  const data = JSON.stringify(obj);
  for (const ws of CLIENTS) {
    if (ws.readyState === ws.OPEN) try { ws.send(data); } catch {}
  }
}

setInterval(() => broadcast(withLive(snapshot())), TICK_MS);

httpServer.listen(HTTP_PORT, '0.0.0.0', () => {
  console.log(`[http] serving on http://localhost:${HTTP_PORT}`);
  console.log(`[ws]   WebSocket at ws://localhost:${HTTP_PORT}/ws  (tick ${TICK_MS}ms)`);
});
