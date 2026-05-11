import { io } from "socket.io-client";

// ✅ Changed port + use 127.0.0.1 (more stable than localhost)
const BRIDGE_URL =
  import.meta.env.VITE_BRIDGE_URL || "http://127.0.0.1:5050";

// ── REST helpers ───────────────────────

async function _get(path) {
  const res = await fetch(`${BRIDGE_URL}${path}`);

  if (!res.ok) {
    throw new Error(`GET ${path} failed: ${res.status}`);
  }

  return res.json();
}

export const fetchStats         = ()      => _get("/api/stats");
export const fetchRecent        = (n=100) => _get(`/api/flows/recent?n=${n}`);
export const fetchAttacks       = (n=100) => _get(`/api/flows/attacks?n=${n}`);
export const fetchRecentSensors = (n=30)  => _get(`/api/sensor/recent?n=${n}`);
export const fetchSensorStats   = ()      => _get("/api/sensor/stats");
export const fetchHealth        = ()      => _get("/api/health");

// ── Socket.IO ─────────────────────────

let _socket = null;

export function getSocket() {
  if (_socket) return _socket;

  _socket = io(BRIDGE_URL, {
    transports: ["websocket", "polling"],
    reconnection: true,
    reconnectionDelay: 2000,
    reconnectionAttempts: Infinity,
  });

  _socket.on("connect", () => {
    console.log("[bridge] Socket connected:", _socket.id);
  });

  _socket.on("disconnect", (reason) => {
    console.warn("[bridge] Socket disconnected:", reason);
  });

  _socket.on("connect_error", (err) => {
    console.warn("[bridge] Connection error:", err.message);
  });

  return _socket;
}

export function onBridgeEvent(event, handler) {
  const socket = getSocket();
  socket.on(event, handler);
  return () => socket.off(event, handler);
}

export function requestRecentFlows(n = 100) {
  getSocket().emit("request_recent", { n });
}

export function disconnectSocket() {
  if (_socket) {
    _socket.disconnect();
    _socket = null;
  }
}