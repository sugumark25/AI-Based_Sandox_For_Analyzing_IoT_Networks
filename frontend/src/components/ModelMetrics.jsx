import { useState, useEffect } from "react";
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell, LineChart, Line, Legend, ReferenceLine,
} from "recharts";
import { fetchRecent, fetchStats } from "../services/api";

const REFRESH_MS = 5000;

const SL = { // section label
  fontFamily:    "var(--font-body)",
  fontSize:      12,
  fontWeight:    700,
  color:         "var(--text-dim)",
  letterSpacing: 1,
  textTransform: "uppercase",
  marginBottom:  18,
};

function Card({ children, style = {} }) {
  return (
    <div style={{
      background: "var(--bg-card)", border: "1px solid var(--border-dim)",
      borderRadius: 8, padding: "24px 28px", ...style,
    }}>
      {children}
    </div>
  );
}

function BigStat({ label, value, sub, accent = "#00d4ff", blink = false }) {
  return (
    <div style={{
      background: "var(--bg-card)", border: "1px solid var(--border-dim)",
      borderTop: `3px solid ${accent}`, borderRadius: 8,
      padding: "24px 26px", position: "relative", overflow: "hidden",
      transition: "background 0.2s",
    }}
      onMouseEnter={e => e.currentTarget.style.background = "var(--bg-hover)"}
      onMouseLeave={e => e.currentTarget.style.background = "var(--bg-card)"}
    >
      <div style={{
        position: "absolute", top: 0, left: 0, right: 0, height: 2,
        background: `linear-gradient(90deg, transparent, ${accent}88, transparent)`,
        animation: "sweep 2.4s ease infinite",
      }} />
      <div style={{ fontFamily:"var(--font-body)", fontSize:12, fontWeight:700, color:"var(--text-dim)", letterSpacing:1, textTransform:"uppercase", marginBottom:12 }}>
        {label}
      </div>
      <div style={{
        fontFamily: "var(--font-display)", fontSize: 32, fontWeight: 800,
        color: accent, lineHeight: 1,
        animation: blink ? "pulse-glow 1.6s ease infinite" : "none",
      }}>{value ?? "--"}</div>
      {sub && <div style={{ fontFamily:"var(--font-body)", fontSize:12, fontWeight:500, color:"var(--text-dim)", marginTop:10 }}>{sub}</div>}
    </div>
  );
}

function MetricRow({ label, value, bar, color = "#00d4ff" }) {
  return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", padding:"13px 0", borderBottom:"1px solid var(--border-dim)" }}>
      <span style={{ fontFamily:"var(--font-body)", fontSize:14, fontWeight:500, color:"var(--text-secondary)" }}>{label}</span>
      <div style={{ display:"flex", alignItems:"center", gap:12 }}>
        {bar !== undefined && (
          <div style={{ width:100, height:4, background:"rgba(255,255,255,0.06)", borderRadius:2 }}>
            <div style={{ width:`${Math.min(bar*100,100)}%`, height:"100%", background:color, boxShadow:`0 0 6px ${color}`, borderRadius:2, transition:"width 0.5s ease" }} />
          </div>
        )}
        <span style={{ fontFamily:"var(--font-mono)", fontSize:13, fontWeight:600, color, minWidth:72, textAlign:"right" }}>{value}</span>
      </div>
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
          {p.name}: <strong>{typeof p.value==="number"?p.value.toFixed(2):p.value}</strong>
        </div>
      ))}
    </div>
  );
}

function ConfidenceHistogram({ rows }) {
  const buckets = Array(10).fill(0).map((_,i) => ({
    range: `${i*10}–${i*10+10}`, count: 0,
    color: i>=8?"#00ff88":i>=5?"#00d4ff":i>=3?"#ffb800":"#ff2d55",
  }));
  rows.forEach(r => {
    const c = parseFloat(r.edge_confidence||0);
    buckets[Math.min(Math.floor(c*10),9)].count++;
  });
  return (
    <div>
      <div style={SL}>Confidence Distribution</div>
      <ResponsiveContainer width="100%" height={170}>
        <BarChart data={buckets} margin={{ top:4, right:4, left:-28, bottom:0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
          <XAxis dataKey="range"
            tick={{ fill:"#3d6680", fontFamily:"'Space Grotesk',sans-serif", fontSize:11, fontWeight:500 }}
            tickLine={false} axisLine={{ stroke:"rgba(0,212,255,0.12)" }} />
          <YAxis tick={{ fill:"#3d6680", fontFamily:"'Space Grotesk',sans-serif", fontSize:11 }} tickLine={false} axisLine={false} />
          <Tooltip content={<ChartTooltip />} cursor={{ fill:"rgba(255,255,255,0.03)" }} />
          <Bar dataKey="count" name="Count" radius={[4,4,0,0]} isAnimationActive={false}>
            {buckets.map((b,i) => <Cell key={i} fill={b.color} style={{ filter:`drop-shadow(0 0 4px ${b.color})` }} />)}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

function ZScoreTimeline({ rows }) {
  const recent = rows.slice(0,60).reverse().map((r,i) => ({
    idx:    i,
    z:      parseFloat(r.z_score||0),
    attack: r.edge_decision==="attack" ? parseFloat(r.z_score||0) : null,
    normal: r.edge_decision!=="attack" ? parseFloat(r.z_score||0) : null,
  }));
  if (recent.length < 2) return <div style={{ ...SL, paddingTop:20 }}>Collecting data...</div>;
  return (
    <div>
      <div style={SL}>Z-Score Timeline — Last 60</div>
      <ResponsiveContainer width="100%" height={170}>
        <LineChart data={recent} margin={{ top:4, right:4, left:-28, bottom:0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" vertical={false} />
          <XAxis dataKey="idx" hide />
          <YAxis tick={{ fill:"#3d6680", fontFamily:"'Space Grotesk',sans-serif", fontSize:11 }} tickLine={false} axisLine={false} />
          <Tooltip content={<ChartTooltip />} cursor={{ stroke:"rgba(0,212,255,0.15)", strokeWidth:1 }} />
          <ReferenceLine y={2} stroke="#ffb800" strokeDasharray="5 3" strokeOpacity={0.6}
            label={{ value:"Z=2.0", fill:"#ffb800", fontSize:10, fontFamily:"'Space Grotesk',sans-serif", fontWeight:600 }} />
          <Line type="monotone" dataKey="normal"  name="Normal Z"  stroke="#00d4ff" strokeWidth={1.5} dot={false} activeDot={{ r:3 }} isAnimationActive={false} connectNulls={false} />
          <Line type="monotone" dataKey="attack"  name="Attack Z"  stroke="#ff2d55" strokeWidth={2}   dot={{ r:3, fill:"#ff2d55" }} activeDot={{ r:4 }} isAnimationActive={false} connectNulls={false} />
          <Legend wrapperStyle={{ fontFamily:"'Space Grotesk',sans-serif", fontSize:12, fontWeight:600, color:"var(--text-dim)", paddingTop:10 }} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

export default function ModelMetrics() {
  const [rows,  setRows]  = useState([]);
  const [stats, setStats] = useState(null);

  async function load() {
    try {
      const [r,s] = await Promise.all([fetchRecent(200), fetchStats()]);
      setRows(r.reverse()); setStats(s);
    } catch {}
  }

  useEffect(() => { load(); const t = setInterval(load, REFRESH_MS); return () => clearInterval(t); }, []);

  const attacks    = rows.filter(r=>r.edge_decision==="attack");
  const normals    = rows.filter(r=>r.edge_decision==="normal");
  const avgConfAtk = attacks.length ? attacks.reduce((s,r)=>s+parseFloat(r.edge_confidence||0),0)/attacks.length : 0;
  const avgConfNrm = normals.length ? normals.reduce((s,r)=>s+parseFloat(r.edge_confidence||0),0)/normals.length : 0;
  const avgZ       = rows.length    ? rows.reduce((s,r)=>s+parseFloat(r.z_score||0),0)/rows.length : 0;
  const highZ      = rows.filter(r=>parseFloat(r.z_score||0)>=2.0).length;
  const attackRate = rows.length ? attacks.length/rows.length : 0;

  return (
    <div style={{ padding:"30px 34px", position:"relative", zIndex:1 }}>

      {/* Header */}
      <div style={{ marginBottom:30 }}>
        <div style={{ fontFamily:"var(--font-display)", fontSize:28, fontWeight:800, color:"var(--accent-green)", letterSpacing:2, textShadow:"var(--glow-green)", marginBottom:6 }}>
          Model Metrics
        </div>
        <div style={{ fontFamily:"var(--font-body)", fontSize:13, fontWeight:500, color:"var(--text-dim)" }}>
          TinyML inference performance — {rows.length} records &nbsp;·&nbsp; Precision 0.9073 &nbsp;·&nbsp; Recall 1.0000 &nbsp;·&nbsp; F1 0.9514
        </div>
      </div>

      {/* Big stat cards */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit, minmax(190px, 1fr))", gap:16, marginBottom:20 }}>
        <BigStat label="Attack Rate"      value={`${(attackRate*100).toFixed(1)}%`} sub={`${attacks.length} of ${rows.length} flows`}     accent="#ff2d55" blink={attackRate>0.1} />
        <BigStat label="Atk Confidence"   value={`${(avgConfAtk*100).toFixed(1)}%`} sub="Attack detections"                                accent="#ffb800" />
        <BigStat label="Norm Confidence"  value={`${(avgConfNrm*100).toFixed(1)}%`} sub="Normal flows"                                     accent="#00ff88" />
        <BigStat label="Avg Z-Score"      value={avgZ.toFixed(3)}                   sub="All flows"                                        accent="#00d4ff" />
        <BigStat label="High-Z Flows"     value={highZ}                             sub="Z-score ≥ 2.0"                                    accent="#9d4edd" />
        <BigStat label="ESP32"
          value={stats?.esp32_status ?? "--"}
          sub={stats?.esp32_last_seen_secs != null ? `${stats.esp32_last_seen_secs}s ago` : ""}
          accent={stats?.esp32_status==="CONNECTED" ? "#00ff88" : "#ff2d55"}
          blink={stats?.esp32_status==="DISCONNECTED"} />
      </div>

      {/* Detail rows */}
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginBottom:20 }}>
        <Card>
          <div style={SL}>Inference Stats</div>
          <MetricRow label="Attack Rate"        value={`${(attackRate*100).toFixed(1)}%`} bar={attackRate}                           color="#ff2d55" />
          <MetricRow label="Avg Conf (Attack)"  value={`${(avgConfAtk*100).toFixed(1)}%`} bar={avgConfAtk}                           color="#ff2d55" />
          <MetricRow label="Avg Conf (Normal)"  value={`${(avgConfNrm*100).toFixed(1)}%`} bar={avgConfNrm}                           color="#00ff88" />
          <MetricRow label="Avg Z-Score"        value={avgZ.toFixed(3)}                   bar={Math.min(avgZ/5,1)}                   color="#00d4ff" />
          <MetricRow label="High-Z Flows ≥ 2"  value={highZ}                             bar={highZ/Math.max(rows.length,1)}        color="#ffb800" />
          <MetricRow label="Total Inferences"   value={rows.length.toLocaleString()}                                                 color="#9d4edd" />
        </Card>
        <Card>
          <div style={SL}>Session Totals</div>
          <MetricRow label="Total Records"    value={stats?.total_records?.toLocaleString()  ?? "--"} color="#00d4ff" />
          <MetricRow label="Attack Records"   value={stats?.attack_records?.toLocaleString() ?? "--"} color="#ff2d55"
            bar={(stats?.attack_records||0)/Math.max(stats?.total_records||1,1)} />
          <MetricRow label="Normal Saved"     value={stats?.normal_records?.toLocaleString()  ?? "--"} color="#00ff88"
            bar={(stats?.normal_records||0)/Math.max(stats?.total_records||1,1)} />
          <MetricRow label="Sensor Readings"  value={stats?.sensor_total?.toLocaleString()    ?? "--"} color="#00d4ff" />
          <MetricRow label="Sensor Alerts"    value={stats?.sensor_alerts?.toLocaleString()   ?? "--"} color="#ffb800" />
          <MetricRow label="ESP32 Status"     value={stats?.esp32_status ?? "--"}
            color={stats?.esp32_status==="CONNECTED"?"#00ff88":"#ff2d55"} />
        </Card>
      </div>

      {/* Model info */}
      <Card style={{ marginBottom:20 }}>
        <div style={SL}>Deployed Model</div>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit, minmax(150px, 1fr))", gap:14 }}>
          {[
            ["Architecture","22→32→16→1","#00d4ff"],
            ["Activation",  "ReLU + Sigmoid","#00ff88"],
            ["Threshold",   "0.50","#ffb800"],
            ["Precision",   "0.9073","#00ff88"],
            ["Recall",      "1.0000","#00ff88"],
            ["F1 Score",    "0.9514","#00ff88"],
            ["Training",    "680N + 75A","#9d4edd"],
            ["Balancing",   "SMOTE","#9d4edd"],
          ].map(([l,v,c]) => (
            <div key={l} style={{ background:"rgba(255,255,255,0.02)", border:"1px solid var(--border-dim)", borderRadius:6, padding:"14px 16px" }}>
              <div style={{ fontFamily:"var(--font-body)", fontSize:11, fontWeight:700, color:"var(--text-dim)", textTransform:"uppercase", letterSpacing:1, marginBottom:8 }}>{l}</div>
              <div style={{ fontFamily:"var(--font-mono)", fontSize:14, fontWeight:600, color:c }}>{v}</div>
            </div>
          ))}
        </div>
      </Card>

      {/* Charts */}
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16 }}>
        <Card><ConfidenceHistogram rows={rows} /></Card>
        <Card><ZScoreTimeline rows={rows} /></Card>
      </div>
    </div>
  );
}