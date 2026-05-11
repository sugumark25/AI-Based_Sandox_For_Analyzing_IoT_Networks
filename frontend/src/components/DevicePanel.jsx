import { useState, useEffect } from "react";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, Legend, ResponsiveContainer,
} from "recharts";
import { fetchStats, fetchRecentSensors } from "../services/api";

const REFRESH_MS = 5000;

function TempGauge({ temp }) {
  const min=20, max=45;
  const pct   = Math.min(Math.max((temp-min)/(max-min),0),1);
  const color = temp>=40?"#ff2d55":temp>=35?"#ffb800":"#00d4ff";
  const r=50, cx=65, cy=65;
  const circ = 2*Math.PI*r;
  const dash = pct*circ*0.75;

  return (
    <div style={{ textAlign:"center" }}>
      <svg width="130" height="110" viewBox="0 0 130 110">
        <circle cx={cx} cy={cy} r={r} fill="none"
          stroke="rgba(255,255,255,0.05)" strokeWidth="10"
          strokeDasharray={`${circ*0.75} ${circ}`}
          strokeDashoffset={circ*0.125}
          strokeLinecap="round" transform={`rotate(135 ${cx} ${cy})`} />
        <circle cx={cx} cy={cy} r={r} fill="none"
          stroke={color} strokeWidth="10"
          strokeDasharray={`${dash} ${circ}`}
          strokeDashoffset={circ*0.125}
          strokeLinecap="round"
          transform={`rotate(135 ${cx} ${cy})`}
          style={{ filter:`drop-shadow(0 0 8px ${color})`, transition:"stroke-dasharray 0.6s ease" }} />
        <text x={cx} y={cy} textAnchor="middle"
          fill={color} fontFamily="'Syne',sans-serif" fontSize="16" fontWeight="800">
          {temp.toFixed(1)}°
        </text>
        <text x={cx} y={cy+18} textAnchor="middle"
          fill="var(--text-dim)" fontFamily="'Space Grotesk',sans-serif" fontSize="10" fontWeight="600">
          Temp °C
        </text>
      </svg>
    </div>
  );
}

function HumBar({ hum }) {
  const color = hum>=80?"#ff2d55":hum>=60?"#ffb800":"#00d4ff";
  return (
    <div>
      <div style={{ display:"flex", justifyContent:"space-between", marginBottom:8 }}>
        <span style={{ fontFamily:"var(--font-body)", fontSize:12, fontWeight:600, color:"var(--text-dim)", textTransform:"uppercase", letterSpacing:1 }}>Humidity</span>
        <span style={{ fontFamily:"var(--font-display)", fontSize:16, color, fontWeight:800 }}>{hum.toFixed(1)}%</span>
      </div>
      <div style={{ height:7, background:"rgba(255,255,255,0.06)", borderRadius:4 }}>
        <div style={{ width:`${hum}%`, height:"100%", background:color, borderRadius:4, boxShadow:`0 0 8px ${color}`, transition:"width 0.6s ease" }} />
      </div>
    </div>
  );
}

function StatusRow({ ok, label, value }) {
  return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", padding:"13px 0", borderBottom:"1px solid var(--border-dim)" }}>
      <div style={{ display:"flex", alignItems:"center", gap:10 }}>
        <div style={{ width:9, height:9, borderRadius:"50%", background:ok?"#00ff88":"#ff2d55", boxShadow:ok?"0 0 8px #00ff88":"0 0 8px #ff2d55", animation:ok?"pulse-glow 2s ease infinite":"none" }} />
        <span style={{ fontFamily:"var(--font-body)", fontSize:13, fontWeight:500, color:"var(--text-dim)" }}>{label}</span>
      </div>
      <span style={{ fontFamily:"var(--font-mono)", fontSize:13, fontWeight:600, color:ok?"#00ff88":"#ff2d55" }}>{value}</span>
    </div>
  );
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div style={{ background:"var(--bg-panel)", border:"1px solid var(--border-mid)", borderRadius:6, padding:"10px 14px", fontFamily:"var(--font-body)", fontSize:13, fontWeight:500 }}>
      <div style={{ color:"var(--text-dim)", marginBottom:6, fontFamily:"var(--font-mono)", fontSize:11 }}>{label}</div>
      {payload.map(p => (
        <div key={p.dataKey} style={{ color:p.color, marginBottom:3 }}>
          {p.name}: <strong>{typeof p.value==="number"?p.value.toFixed(1):p.value}</strong>
        </div>
      ))}
    </div>
  );
}

export default function DevicePanel() {
  const [stats,   setStats]   = useState(null);
  const [sensors, setSensors] = useState([]);

  async function load() {
    try {
      const [s,sr] = await Promise.all([fetchStats(), fetchRecentSensors(30)]);
      setStats(s); setSensors(Array.isArray(sr)?sr:[]);
    } catch {}
  }

  useEffect(() => { load(); const t = setInterval(load, REFRESH_MS); return () => clearInterval(t); }, []);

  const latest   = sensors[sensors.length-1];
  const temp     = parseFloat(latest?.temp      || 0);
  const hum      = parseFloat(latest?.hum       || 0);
  const heatIdx  = parseFloat(latest?.heatIndex || 0);
  const label    = latest?.label || "--";
  const labelColor = label==="HOT"?"#ff2d55":label==="WARM"?"#ffb800":label==="HUMID"?"#9d4edd":label==="COOL"?"#00d4ff":"#00ff88";

  // Build chart data from sensor history
  const chartData = sensors.map((r,i) => ({
    idx:  i,
    temp: parseFloat(r.temp      || 0),
    hum:  parseFloat(r.hum       || 0),
    heat: parseFloat(r.heatIndex || 0),
  }));

  return (
    <div style={{ padding:"30px 34px", position:"relative", zIndex:1 }}>

      {/* Header */}
      <div style={{ marginBottom:28 }}>
        <div style={{ fontFamily:"var(--font-display)", fontSize:28, fontWeight:800, color:"#ffb800", letterSpacing:2, marginBottom:6 }}>
          Device Panel
        </div>
        <div style={{ fontFamily:"var(--font-body)", fontSize:13, fontWeight:500, color:"var(--text-dim)" }}>
          ESP32E-01 · Hardware status · Sensor readings
        </div>
      </div>

      {/* Top 3 cards */}
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:16, marginBottom:16 }}>

        {/* Connection status */}
        <div style={{ background:"var(--bg-card)", border:"1px solid var(--border-dim)", borderRadius:8, padding:"22px 24px" }}>
          <div style={{ fontFamily:"var(--font-body)", fontSize:12, fontWeight:700, color:"var(--text-dim)", letterSpacing:1, textTransform:"uppercase", marginBottom:16 }}>
            Connection Status
          </div>
          <StatusRow ok={stats?.esp32_status==="CONNECTED"}              label="ESP32"     value={stats?.esp32_status ?? "--"} />
          <StatusRow ok={stats?.esp32_last_seen_secs!=null&&stats.esp32_last_seen_secs<30} label="Last Seen" value={stats?.esp32_last_seen_secs!=null?`${stats.esp32_last_seen_secs}s`:"--"} />
          <StatusRow ok={stats?.total_records>0}                         label="Data Flow" value={`${stats?.total_records??0} flows`} />
          <StatusRow ok={true}                                           label="MQTT"      value="Active" />
        </div>

        {/* Live sensor */}
        <div style={{ background:"var(--bg-card)", border:"1px solid var(--border-dim)", borderRadius:8, padding:"22px 24px", display:"flex", flexDirection:"column", gap:18 }}>
          <div style={{ fontFamily:"var(--font-body)", fontSize:12, fontWeight:700, color:"var(--text-dim)", letterSpacing:1, textTransform:"uppercase" }}>
            Live Sensor
          </div>
          <TempGauge temp={temp||25} />
          <HumBar    hum={hum||50} />
        </div>

        {/* Readings */}
        <div style={{ background:"var(--bg-card)", border:"1px solid var(--border-dim)", borderRadius:8, padding:"22px 24px" }}>
          <div style={{ fontFamily:"var(--font-body)", fontSize:12, fontWeight:700, color:"var(--text-dim)", letterSpacing:1, textTransform:"uppercase", marginBottom:16 }}>
            Readings
          </div>
          {[
            ["Temperature", `${temp.toFixed(1)} °C`,    "#ff2d55"],
            ["Humidity",    `${hum.toFixed(1)} %`,      "#00d4ff"],
            ["Heat Index",  `${heatIdx.toFixed(1)} °C`, "#ffb800"],
            ["Status",      label,                       labelColor],
            ["Sensor Total",`${stats?.sensor_total??0}`, "#9d4edd"],
            ["Alerts",      `${stats?.sensor_alerts??0}`,"#ff2d55"],
          ].map(([l,v,c]) => (
            <div key={l} style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"10px 0", borderBottom:"1px solid var(--border-dim)" }}>
              <span style={{ fontFamily:"var(--font-body)", fontSize:13, fontWeight:500, color:"var(--text-dim)" }}>{l}</span>
              <span style={{ fontFamily:"var(--font-mono)", fontSize:13, fontWeight:600, color:c }}>{v}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Sensor history chart */}
      <div style={{ background:"var(--bg-card)", border:"1px solid var(--border-dim)", borderRadius:8, padding:"22px 26px", marginBottom:16 }}>
        <div style={{ fontFamily:"var(--font-body)", fontSize:12, fontWeight:700, color:"var(--text-dim)", letterSpacing:1, textTransform:"uppercase", marginBottom:18 }}>
          Sensor History — Last {sensors.length} readings
        </div>
        {chartData.length < 2 ? (
          <div style={{ fontFamily:"var(--font-body)", fontSize:13, color:"var(--text-dim)", padding:"20px 0" }}>
            Waiting for sensor data...
          </div>
        ) : (
          <ResponsiveContainer width="100%" height={180}>
            <LineChart data={chartData} margin={{ top:4, right:16, left:-20, bottom:0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
              <XAxis dataKey="idx" hide />
              <YAxis tick={{ fill:"#3d6680", fontFamily:"'Space Grotesk',sans-serif", fontSize:11 }} tickLine={false} axisLine={false} />
              <Tooltip content={<ChartTooltip />} cursor={{ stroke:"rgba(0,212,255,0.15)", strokeWidth:1 }} />
              <Legend wrapperStyle={{ fontFamily:"'Space Grotesk',sans-serif", fontSize:12, fontWeight:600, color:"var(--text-dim)", paddingTop:10 }} />
              <Line type="monotone" dataKey="temp" name="Temp °C"   stroke="#ff2d55" strokeWidth={2} dot={false} activeDot={{ r:4 }} isAnimationActive={false} />
              <Line type="monotone" dataKey="hum"  name="Humidity %" stroke="#00d4ff" strokeWidth={2} dot={false} activeDot={{ r:4 }} isAnimationActive={false} />
              <Line type="monotone" dataKey="heat" name="Heat Index" stroke="#ffb800" strokeWidth={1.5} strokeDasharray="4 2" dot={false} activeDot={{ r:3 }} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>

      {/* Sensor log table */}
      {sensors.length > 0 && (
        <div style={{ background:"var(--bg-card)", border:"1px solid var(--border-dim)", borderRadius:8, overflow:"hidden" }}>
          <div style={{ overflowY:"auto", maxHeight:240 }}>
            <table style={{ width:"100%", borderCollapse:"collapse" }}>
              <thead>
                <tr>
                  {["Time","Temp (°C)","Humidity (%)","Heat Index","Label"].map(h => (
                    <th key={h} style={{
                      padding:"11px 16px",
                      fontFamily:"var(--font-body)", fontSize:11, fontWeight:700,
                      color:"var(--text-dim)", letterSpacing:0.5, textTransform:"uppercase",
                      borderBottom:"1px solid var(--border-mid)",
                      background:"var(--bg-deep)", position:"sticky", top:0, textAlign:"left",
                    }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {[...sensors].reverse().map((r,i) => {
                  const lc=r.label==="HOT"?"#ff2d55":r.label==="WARM"?"#ffb800":r.label==="HUMID"?"#9d4edd":r.label==="COOL"?"#00d4ff":"#00ff88";
                  return (
                    <tr key={i} style={{ borderBottom:"1px solid var(--border-dim)" }}>
                      <td style={{ padding:"10px 16px", fontFamily:"var(--font-mono)", fontSize:12, color:"var(--text-secondary)" }}>{r.timestamp?.slice(11,19)}</td>
                      <td style={{ padding:"10px 16px", fontFamily:"var(--font-mono)", fontSize:12, color:"#ff2d55" }}>{parseFloat(r.temp||0).toFixed(1)}</td>
                      <td style={{ padding:"10px 16px", fontFamily:"var(--font-mono)", fontSize:12, color:"#00d4ff" }}>{parseFloat(r.hum||0).toFixed(1)}</td>
                      <td style={{ padding:"10px 16px", fontFamily:"var(--font-mono)", fontSize:12, color:"#ffb800" }}>{parseFloat(r.heatIndex||0).toFixed(1)}</td>
                      <td style={{ padding:"10px 16px" }}>
                        <span style={{ fontFamily:"var(--font-body)", fontSize:11, fontWeight:700, color:lc, background:`${lc}14`, padding:"3px 10px", borderRadius:4, border:`1px solid ${lc}44` }}>
                          {r.label}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}