import { useState } from "react";
import Dashboard       from "./components/Dashboard";
import TrafficAnalysis from "./components/TrafficAnalysis";
import ModelMetrics    from "./components/ModelMetrics";
import DevicePanel     from "./components/DevicePanel";
import AlertsPanel     from "./components/AlertsPanel";
import MirroredSamplesPanel from "./components/MirroredSamplesPanel";
import "./styles/global.css";

const NAV = [
  { key: "dashboard", label: "Dashboard",  icon: "◈", color: "#00d4ff" },
  { key: "traffic",   label: "Traffic",    icon: "◉", color: "#00d4ff" },
  { key: "model",     label: "ML Metrics", icon: "◆", color: "#00ff88" },
  { key: "device",    label: "Device",     icon: "◎", color: "#ffb800" },
  { key: "alerts",    label: "Alerts",     icon: "⚠", color: "#ff2d55" },
  { key: "mirrors",   label: "Mirrors",    icon: "✉", color: "#8e6cff" },
];

export default function App() {
  const [active, setActive] = useState("dashboard");

  return (
    <div style={{ minHeight: "100vh", display: "flex", flexDirection: "column" }}>
      <div className="scanline" />

      {/* ── Top nav ─────────────────────────────────────────── */}
      <nav style={{
        background:   "var(--bg-deep)",
        borderBottom: "1px solid var(--border-mid)",
        padding:      "0 32px",
        display:      "flex",
        alignItems:   "center",
        gap:          0,
        position:     "sticky",
        top:          0,
        zIndex:       100,
        boxShadow:    "0 2px 24px rgba(0,212,255,0.08)",
      }}>
        {/* Logo */}
        <div style={{
          fontFamily:    "var(--font-display)",
          fontSize:      16,
          fontWeight:    800,
          color:         "var(--accent-cyan)",
          letterSpacing: 5,
          padding:       "18px 0",
          marginRight:   40,
          textShadow:    "var(--glow-cyan)",
          borderBottom:  "2px solid var(--accent-cyan)",
        }}>
          ESP32 · IDS
        </div>

        {/* Nav items */}
        {NAV.map(n => {
          const isActive = active === n.key;
          return (
            <button key={n.key} onClick={() => setActive(n.key)} style={{
              background:    "transparent",
              border:        "none",
              borderBottom:  isActive ? `2px solid ${n.color}` : "2px solid transparent",
              color:         isActive ? n.color : "var(--text-dim)",
              fontFamily:    "var(--font-body)",
              fontSize:      13,
              fontWeight:    600,
              letterSpacing: 0.5,
              padding:       "20px 20px",
              cursor:        "pointer",
              transition:    "color 0.2s, border-color 0.2s",
              display:       "flex",
              alignItems:    "center",
              gap:           7,
            }}
              onMouseEnter={e => { if (!isActive) e.currentTarget.style.color = "var(--text-secondary)"; }}
              onMouseLeave={e => { if (!isActive) e.currentTarget.style.color = "var(--text-dim)"; }}
            >
              <span style={{ fontSize: 12, textShadow: isActive ? `0 0 8px ${n.color}` : "none" }}>
                {n.icon}
              </span>
              {n.label}
            </button>
          );
        })}

        {/* Live indicator */}
        <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 8 }}>
          <div style={{
            width: 8, height: 8, borderRadius: "50%",
            background: "#00ff88",
            boxShadow:  "0 0 8px #00ff88",
            animation:  "pulse-glow 1.5s ease infinite",
          }} />
          <span style={{
            fontFamily:    "var(--font-body)",
            fontSize:      12,
            fontWeight:    600,
            color:         "var(--text-dim)",
            letterSpacing: 1,
          }}>Live</span>
        </div>
      </nav>

      {/* ── Page content ────────────────────────────────────── */}
      <main style={{ flex: 1, position: "relative", zIndex: 1 }}>
        {active === "dashboard" && <Dashboard   onNavigate={setActive} />}
        {active === "traffic"   && <TrafficAnalysis />}
        {active === "model"     && <ModelMetrics />}
        {active === "device"    && <DevicePanel />}
        {active === "alerts"    && <AlertsPanel />}
        {active === "mirrors"   && <MirroredSamplesPanel />}
      </main>

      {/* ── Footer ──────────────────────────────────────────── */}
      <footer style={{
        borderTop:      "1px solid var(--border-dim)",
        padding:        "12px 32px",
        display:        "flex",
        justifyContent: "space-between",
        alignItems:     "center",
        background:     "var(--bg-deep)",
      }}>
        <span style={{
          fontFamily:    "var(--font-body)",
          fontSize:      12,
          fontWeight:    500,
          color:         "var(--text-dim)",
          letterSpacing: 0.5,
        }}>
          ESP32 Edge IDS · TinyML · MQTT · Real-Time
        </span>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-dim)" }}>
          {new Date().toISOString().slice(0, 19).replace("T", " ")} UTC
        </span>
      </footer>
    </div>
  );
}