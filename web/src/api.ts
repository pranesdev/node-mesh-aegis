// api.ts — WS stream from /ws. Exposes tick + tick src/target + simple stats.

import { useEffect, useState } from 'react';
import type { TickPayload } from './types';

let socket: WebSocket | null = null;
let stats = { sent: { rssi: 0, etx: 0 }, delivered: { rssi: 0, etx: 0 } };
let retryTimer: number | null = null;
const tickSubs = new Set<(p: TickPayload) => void>();
const statsSubs = new Set<(s: typeof stats) => void>();

function openSocket() {
  if (socket && socket.readyState <= WebSocket.OPEN) return;
  if (retryTimer) { clearTimeout(retryTimer); retryTimer = null; }
  const target = import.meta.env.VITE_WS_URL || 'wss://node-mesh-aegis.onrender.com/ws';
  socket = new WebSocket(target);
  socket.onmessage = (ev) => {
    let m: any;
    try { m = JSON.parse(ev.data); } catch { return; }
    if (m.cmd === 'stats_reset') {
      stats = { sent: { rssi: 0, etx: 0 }, delivered: { rssi: 0, etx: 0 } };
      statsSubs.forEach((cb) => cb(stats));
      return;
    }
    if (m.cmd !== 'tick') return;
    tickSubs.forEach((cb) => cb(m as TickPayload));
  };
  socket.onclose = () => { retryTimer = window.setTimeout(openSocket, 1000); };
  socket.onerror = () => { /* close handler will reschedule */ };
  socket.onopen = () => { if (retryTimer) { clearTimeout(retryTimer); retryTimer = null; } };
}
openSocket();

export function useMeshStream(): { tick: TickPayload | null; stats: typeof stats } {
  const [tick, setTick] = useState<TickPayload | null>(null);
  const [s, setS] = useState(stats);
  useEffect(() => {
    tickSubs.add(setTick as any);
    statsSubs.add(setS);
    return () => {
      tickSubs.delete(setTick as any);
      statsSubs.delete(setS);
    };
  }, []);
  return { tick, stats: s };
}

export function send(msg: any) {
  if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify(msg));
}

export function reportTick(mode: 'rssi' | 'etx', explored: number, delivered: boolean) {
  stats.sent[mode] += 1;
  if (delivered) stats.delivered[mode] += 1;
  statsSubs.forEach((cb) => cb(stats));
}

export function resetClientStats() {
  stats = { sent: { rssi: 0, etx: 0 }, delivered: { rssi: 0, etx: 0 } };
  statsSubs.forEach((cb) => cb(stats));
}
