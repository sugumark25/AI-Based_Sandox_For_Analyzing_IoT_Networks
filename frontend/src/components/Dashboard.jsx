import { useState, useEffect, useRef } from "react";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer,
} from "recharts";
import { fetchStats } from "../services/api";

const REFRESH_MS = 3000;

const LIGHT_VARS = `
  --bg-void:#f0f4f8;--bg-deep:#e2e8f0;--bg-panel:#dde3ec;--bg-card:#ffffff;--bg-hover:#f7fafc;
  --accent-cyan:#0077cc;--accent-green:#22863a;--accent-red:#e53e3e;--accent-amber:#b7791f;--accent-purple:#6b46c1;
  --border-dim:rgba(0,100,180,0.12);--border-mid:rgba(0,100,180,0.25);--border-bright:rgba(0,100,180,0.5);
  --text-primary:#1a202c;--text-secondary:#2d4a6b;--text-dim:#718096;
  --glow-cyan:0 0 12px rgba(0,119,204,0.15);--glow-green:0 0 12px rgba(34,134,58,0.15);--glow-red:0 0 12px rgba(229,62,62,0.2);
`;

function StatCard({ label, value, sub, accent = "cyan", blink = false }) {
  const v = `var(--accent-${accent})`;
  return (
    <div className="animate-in" style={{
      background:   "var(--bg-card)",
      border:       "1px solid var(--border-dim)",
      borderTop:    `3px solid ${v}`,
      borderRadius: 8,
      padding:      "24px 26px",
      position:     "relative",
      overflow:     "hidden",
      transition:   "background 0.2s",
    }}
      onMouseEnter={e => e.currentTarget.style.background = "var(--bg-hover)"}
      onMouseLeave={e => e.currentTarget.style.background = "var(--bg-card)"}
    >
      <div style={{
        position:   "absolute", top: 0, left: 0, right: 0, height: 2,
        background: `linear-gradient(90deg, transparent, ${v}, transparent)`,
        animation:  "sweep 2.4s ease infinite",
      }} />
      <div style={{
        fontFamily:    "var(--font-body)",
        fontSize:      12,
        fontWeight:    600,
        color:         "var(--text-dim)",
        letterSpacing: 1,
        textTransform: "uppercase",
        marginBottom:  12,
      }}>{label}</div>
      <div style={{
        fontFamily: "var(--font-display)",
        fontSize:   32,
        fontWeight: 800,
        color:      v,
        lineHeight: 1,
        animation:  blink ? "pulse-glow 1.6s ease infinite" : "none",
      }}>{value ?? "--"}</div>
      {sub && (
        <div style={{
          fontFamily:  "var(--font-body)",
          fontSize:    12,
          fontWeight:  500,
          color:       "var(--text-dim)",
          marginTop:   10,
        }}>{sub}</div>
      )}
    </div>
  );
}

function AttackRateGauge({ pct }) {
  const hex   = pct > 40 ? "#ff2d55" : pct > 20 ? "#ffb800" : "#00ff88";
  const angle = (pct / 100) * 180;
  return (
    <div style={{ textAlign: "center" }}>
      <svg width="170" height="100" viewBox="0 0 170 100">
        <path d="M 12 88 A 75 75 0 0 1 158 88"
          fill="none" stroke="rgba(0,212,255,0.1)" strokeWidth="14" strokeLinecap="round" />
        <path d="M 12 88 A 75 75 0 0 1 158 88"
          fill="none" stroke={hex} strokeWidth="14" strokeLinecap="round"
          strokeDasharray={`${(angle / 180) * 235.6} 235.6`}
          style={{ filter: `drop-shadow(0 0 6px ${hex})`, transition: "stroke-dasharray 0.8s ease" }}
        />
        <text x="85" y="78" textAnchor="middle"
          fill={hex} fontFamily="'Syne',sans-serif" fontSize="22" fontWeight="800">
          {pct.toFixed(1)}%
        </text>
        <text x="85" y="94" textAnchor="middle"
          fill="var(--text-dim)" fontFamily="'Space Grotesk',sans-serif" fontSize="10" fontWeight="600">
          Attack Rate
        </text>
      </svg>
    </div>
  );
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{
      background:   "var(--bg-panel)",
      border:       "1px solid var(--border-mid)",
      borderRadius: 6,
      padding:      "10px 14px",
      fontFamily:   "var(--font-body)",
      fontSize:     13,
      fontWeight:   500,
    }}>
      <div style={{ color: "var(--text-dim)", marginBottom: 6, fontFamily: "var(--font-mono)", fontSize: 11 }}>{label}</div>
      {payload.map(p => (
        <div key={p.dataKey} style={{ color: p.color, marginBottom: 3 }}>
          {p.name}: <strong>{p.value}</strong>
        </div>
      ))}
    </div>
  );
}

function ThemeToggle({ darkMode, onToggle }) {
  return (
    <button onClick={onToggle} style={{
      background:   "var(--bg-card)",
      border:       "1px solid var(--border-mid)",
      borderRadius: 20,
      padding:      "8px 18px",
      cursor:       "pointer",
      color:        "var(--text-secondary)",
      fontFamily:   "var(--font-body)",
      fontSize:     13,
      fontWeight:   600,
      display:      "flex",
      alignItems:   "center",
      gap:          8,
      transition:   "border-color 0.2s",
    }}
      onMouseEnter={e => e.currentTarget.style.borderColor = "var(--border-bright)"}
      onMouseLeave={e => e.currentTarget.style.borderColor = "var(--border-mid)"}
    >
      <span style={{ fontSize: 15 }}>{darkMode ? "☀" : "☾"}</span>
      {darkMode ? "Light" : "Dark"}
    </button>
  );
}

export default function Dashboard({ onNavigate }) {
  const [stats,    setStats]    = useState(null);
  const [history,  setHistory]  = useState([]);
  const [error,    setError]    = useState(null);
  const [tick,     setTick]     = useState(0);
  const [darkMode, setDarkMode] = useState(true);
  const timerRef = useRef(null);
  const styleRef = useRef(null);

  useEffect(() => {
    if (!styleRef.current) {
      styleRef.current = document.createElement("style");
      document.head.appendChild(styleRef.current);
    }
    styleRef.current.textContent = darkMode ? "" : `:root { ${LIGHT_VARS} }`;
  }, [darkMode]);

  async function load() {
    try {
      const s = await fetchStats();
      setStats(s); setError(null); setTick(n => n + 1);
      setHistory(h => {
        const now = new Date();
        const ts  = `${now.getHours().toString().padStart(2,"0")}:`
                  + `${now.getMinutes().toString().padStart(2,"0")}:`
                  + `${now.getSeconds().toString().padStart(2,"0")}`;
        return [...h, {
          time: ts,
          attacks: s.attack_records ?? 0,
          normal:  s.normal_records  ?? 0,
          sensors: s.sensor_total    ?? 0,
        }].slice(-40);
      });
    } catch { setError("Backend unreachable"); }
  }

  useEffect(() => {
    load();
    timerRef.current = setInterval(load, REFRESH_MS);
    return () => clearInterval(timerRef.current);
  }, []);

  const attackRate  = stats ? (stats.attack_records / Math.max(stats.total_records, 1)) * 100 : 0;
  const esp32Accent = stats?.esp32_status === "CONNECTED" ? "green" : stats?.esp32_status === "DISCONNECTED" ? "red" : "amber";

  return (
    <div style={{ padding: "30px 34px", position: "relative", zIndex: 1 }}>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 32 }}>
        <div>
          <div style={{
            fontFamily: "var(--font-display)", fontSize: 28, fontWeight: 800,
            color: "var(--accent-cyan)", letterSpacing: 2, textShadow: "var(--glow-cyan)",
          }}>Edge IDS — Live Dashboard</div>
          <div style={{ fontFamily: "var(--font-body)", fontSize: 13, fontWeight: 500, color: "var(--text-dim)", marginTop: 6 }}>
            ESP32 · TinyML · Real-Time · Auto-refresh every {REFRESH_MS / 1000}s
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          {error && (
            <div style={{
              fontFamily: "var(--font-body)", fontSize: 13, fontWeight: 600,
              color: "var(--accent-red)", border: "1px solid var(--accent-red)",
              padding: "6px 14px", borderRadius: 4, animation: "pulse-glow 1s ease infinite",
            }}>⚠ {error}</div>
          )}
          <div style={{ fontFamily: "var(--font-mono)", fontSize: 12, color: "var(--text-dim)" }}>#{tick}</div>
          <ThemeToggle darkMode={darkMode} onToggle={() => setDarkMode(d => !d)} />
        </div>
      </div>

      {/* Row 1 */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: 16, marginBottom: 16 }}>
        <StatCard label="Total Flows"     value={stats?.total_records?.toLocaleString()}  accent="cyan"  />
        <StatCard label="Attacks"         value={stats?.attack_records?.toLocaleString()} accent="red"   blink={stats?.attack_records > 0} />
        <StatCard label="Normal Saved"    value={stats?.normal_records?.toLocaleString()} accent="green" />
        <StatCard label="Sensor Readings" value={stats?.sensor_total?.toLocaleString()}   accent="cyan"  />
        <StatCard label="Sensor Alerts"   value={stats?.sensor_alerts?.toLocaleString()}  accent="amber" blink={stats?.sensor_alerts > 0} />
      </div>

      {/* Row 2 */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(190px, 1fr))", gap: 16, marginBottom: 24 }}>
        <StatCard label="Last Seen"
          value={stats?.esp32_last_seen_secs != null ? `${stats.esp32_last_seen_secs}s ago` : "N/A"}
          accent="cyan" />
        <StatCard label="ESP32 Status"  value={stats?.esp32_status ?? "UNKNOWN"} accent={esp32Accent} blink={stats?.esp32_status === "DISCONNECTED"} />
        <StatCard label="Attack Rate"   value={`${attackRate.toFixed(2)}%`} accent={attackRate > 40 ? "red" : attackRate > 20 ? "amber" : "green"} />
      </div>

      {/* Gauge + Line chart */}
      <div style={{ display: "grid", gridTemplateColumns: "220px 1fr", gap: 16, marginBottom: 24 }}>
        <div style={{
          background: "var(--bg-card)", border: "1px solid var(--border-dim)", borderRadius: 8,
          padding: "24px 18px", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
        }}>
          <AttackRateGauge pct={attackRate} />
          <div style={{ fontFamily: "var(--font-body)", fontSize: 12, fontWeight: 500, color: "var(--text-dim)", marginTop: 12, textAlign: "center" }}>
            {stats?.attack_records ?? 0} attacks / {stats?.total_records ?? 0} total
          </div>
        </div>

        <div style={{ background: "var(--bg-card)", border: "1px solid var(--border-dim)", borderRadius: 8, padding: "22px 26px" }}>
          <div style={{ fontFamily: "var(--font-body)", fontSize: 13, fontWeight: 600, color: "var(--text-dim)", letterSpacing: 0.5, textTransform: "uppercase", marginBottom: 18 }}>
            Live Flow Trend — Last {history.length} samples
          </div>
          {history.length < 2 ? (
            <div style={{ fontFamily: "var(--font-body)", fontSize: 13, color: "var(--text-dim)", paddingTop: 20 }}>Collecting data...</div>
          ) : (
            <ResponsiveContainer width="100%" height={180}>
              <LineChart data={history} margin={{ top: 4, right: 16, left: -20, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(0,212,255,0.06)" vertical={false} />
                <XAxis dataKey="time"
                  tick={{ fill: "#3d6680", fontFamily: "'Space Grotesk',sans-serif", fontSize: 11, fontWeight: 500 }}
                  tickLine={false} axisLine={{ stroke: "rgba(0,212,255,0.12)" }} interval="preserveStartEnd" />
                <YAxis
                  tick={{ fill: "#3d6680", fontFamily: "'Space Grotesk',sans-serif", fontSize: 11 }}
                  tickLine={false} axisLine={false} />
                <Tooltip content={<ChartTooltip />} cursor={{ stroke: "rgba(0,212,255,0.15)", strokeWidth: 1 }} />
                <Legend wrapperStyle={{ fontFamily: "'Space Grotesk',sans-serif", fontSize: 12, fontWeight: 600, color: "#3d6680", paddingTop: 10 }} />
                <Line type="monotone" dataKey="normal"  name="Normal"  stroke="#00ff88" strokeWidth={2} dot={false} activeDot={{ r: 4 }} style={{ filter: "drop-shadow(0 0 4px #00ff88)" }} isAnimationActive={false} />
                <Line type="monotone" dataKey="attacks" name="Attacks" stroke="#ff2d55" strokeWidth={2} dot={false} activeDot={{ r: 4 }} style={{ filter: "drop-shadow(0 0 4px #ff2d55)" }} isAnimationActive={false} />
                <Line type="monotone" dataKey="sensors" name="Sensors" stroke="#ffb800" strokeWidth={1.5} strokeDasharray="4 2" dot={false} activeDot={{ r: 3 }} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Quick nav */}
      <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
        {[
          { label: "Traffic Analysis", key: "traffic", color: "var(--accent-cyan)"  },
          { label: "Model Metrics",    key: "model",   color: "var(--accent-green)" },
          { label: "Device Panel",     key: "device",  color: "var(--accent-amber)" },
          { label: "Alerts",           key: "alerts",  color: "var(--accent-red)"   },
        ].map(btn => (
          <button key={btn.key} onClick={() => onNavigate?.(btn.key)} style={{
            background: "transparent", border: `1px solid ${btn.color}`, color: btn.color,
            fontFamily: "var(--font-body)", fontSize: 13, fontWeight: 600, letterSpacing: 0.5,
            padding: "10px 24px", borderRadius: 6, cursor: "pointer", textTransform: "uppercase",
            transition: "background 0.2s, box-shadow 0.2s",
          }}
            onMouseEnter={e => { e.currentTarget.style.background = `${btn.color}18`; e.currentTarget.style.boxShadow = `0 0 14px ${btn.color}44`; }}
            onMouseLeave={e => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.boxShadow = "none"; }}
          >▶ {btn.label}</button>
        ))}
      </div>
    </div>
  );
}