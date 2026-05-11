import { useState, useEffect } from "react";
import { fetchRecent } from "../services/api";

const REFRESH_MS = 4000;

const td = {
  padding:    "12px 16px",
  fontFamily: "var(--font-mono)",
  fontSize:   12,
  color:      "var(--text-secondary)",
  whiteSpace: "nowrap",
};

const th = {
  padding:       "12px 16px",
  fontFamily:    "var(--font-body)",
  fontSize:      11,
  fontWeight:    700,
  color:         "var(--text-dim)",
  letterSpacing: 0.5,
  textTransform: "uppercase",
  borderBottom:  "1px solid var(--border-mid)",
  background:    "var(--bg-deep)",
  position:      "sticky",
  top:           0,
  whiteSpace:    "nowrap",
};

function ConfBar({ value, color }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
      <div style={{ width: 72, height: 5, background: "rgba(255,255,255,0.06)", borderRadius: 3, overflow: "hidden" }}>
        <div style={{
          width: `${value * 100}%`, height: "100%", background: color,
          boxShadow: `0 0 6px ${color}`, transition: "width 0.4s ease",
        }} />
      </div>
      <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, color: "var(--text-dim)" }}>
        {(value * 100).toFixed(0)}%
      </span>
    </div>
  );
}

function FlowRow({ row, index }) {
  const isAttack = row.edge_decision === "attack";
  const conf     = parseFloat(row.edge_confidence || 0);
  const z        = parseFloat(row.z_score || 0);
  return (
    <tr style={{
      borderBottom: "1px solid var(--border-dim)",
      background: isAttack
        ? `rgba(255,45,85,${0.04 + index % 2 * 0.02})`
        : `rgba(0,255,136,${0.02 + index % 2 * 0.01})`,
      animation: index === 0 ? "slide-in 0.3s ease" : "none",
    }}>
      <td style={{ ...td, fontFamily: "var(--font-mono)", fontSize: 11 }}>{row.timestamp?.slice(11, 23)}</td>
      <td style={td}>
        <span style={{
          fontFamily:    "var(--font-body)",
          fontSize:      12,
          fontWeight:    700,
          color:         isAttack ? "#ff2d55" : "#00ff88",
          background:    isAttack ? "rgba(255,45,85,0.12)" : "rgba(0,255,136,0.08)",
          padding:       "3px 10px", borderRadius: 4,
          border:        `1px solid ${isAttack ? "rgba(255,45,85,0.3)" : "rgba(0,255,136,0.2)"}`,
          textShadow:    isAttack ? "0 0 8px #ff2d55" : "0 0 8px #00ff88",
        }}>
          {isAttack ? "⚠ Attack" : "✓ Normal"}
        </span>
      </td>
      <td style={td}><ConfBar value={conf} color={isAttack ? "#ff2d55" : "#00ff88"} /></td>
      <td style={{ ...td, color: z > 2 ? "#ffb800" : "var(--text-secondary)" }}>{z.toFixed(3)}</td>
      <td style={td}>{parseFloat(row.packet_rate || 0).toFixed(1)}</td>
      <td style={td}>{parseFloat(row.byte_rate   || 0).toFixed(0)}</td>
      <td style={td}>{row.src_bytes || 0}</td>
      <td style={td}>{row.src_pkts  || 0}</td>
      <td style={td}>{row.proto_tcp==1?"TCP":row.proto_udp==1?"UDP":row.proto_icmp==1?"ICMP":"?"}</td>
      <td style={td}>{parseFloat(row.duration || 0).toFixed(3)}s</td>
    </tr>
  );
}

function ProtocolBar({ rows }) {
  const counts = rows.reduce((acc, r) => {
    const p = r.proto_tcp==1?"TCP":r.proto_udp==1?"UDP":r.proto_icmp==1?"ICMP":"OTHER";
    acc[p] = (acc[p] || 0) + 1; return acc;
  }, {});
  const total  = rows.length || 1;
  const colors = { TCP:"#00d4ff", UDP:"#00ff88", ICMP:"#ffb800", OTHER:"#9d4edd" };
  return (
    <div style={{ background:"var(--bg-card)", border:"1px solid var(--border-dim)", borderRadius:8, padding:"20px 24px" }}>
      <div style={{ fontFamily:"var(--font-body)", fontSize:12, fontWeight:700, color:"var(--text-dim)", letterSpacing:1, textTransform:"uppercase", marginBottom:14 }}>
        Protocol Distribution
      </div>
      <div style={{ display:"flex", height:8, borderRadius:4, overflow:"hidden", gap:2, marginBottom:14 }}>
        {Object.entries(counts).map(([p,c]) => (
          <div key={p} style={{ width:`${(c/total)*100}%`, background:colors[p]||"#666", boxShadow:`0 0 8px ${colors[p]}`, transition:"width 0.6s ease" }} />
        ))}
      </div>
      <div style={{ display:"flex", gap:28 }}>
        {Object.entries(counts).map(([p,c]) => (
          <div key={p} style={{ display:"flex", alignItems:"center", gap:8 }}>
            <div style={{ width:10, height:10, borderRadius:2, background:colors[p]||"#666" }} />
            <span style={{ fontFamily:"var(--font-body)", fontSize:13, fontWeight:500, color:"var(--text-dim)" }}>
              {p} — {((c/total)*100).toFixed(1)}%
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function TrafficAnalysis() {
  const [rows,   setRows]   = useState([]);
  const [filter, setFilter] = useState("all");
  const [paused, setPaused] = useState(false);
  const [counts, setCounts] = useState({ attack:0, normal:0 });

  async function load() {
    if (paused) return;
    try {
      const data = await fetchRecent(200);
      setRows(data.reverse());
      const a = data.filter(r => r.edge_decision === "attack").length;
      setCounts({ attack:a, normal:data.length-a });
    } catch {}
  }

  useEffect(() => { load(); const t = setInterval(load, REFRESH_MS); return () => clearInterval(t); }, [paused]);

  const filtered = filter==="all" ? rows : filter==="attack" ? rows.filter(r=>r.edge_decision==="attack") : rows.filter(r=>r.edge_decision==="normal");

  return (
    <div style={{ padding:"30px 34px", position:"relative", zIndex:1 }}>

      {/* Header */}
      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:24 }}>
        <div>
          <div style={{ fontFamily:"var(--font-display)", fontSize:26, fontWeight:800, color:"var(--accent-cyan)", letterSpacing:2 }}>
            Traffic Analysis
          </div>
          <div style={{ fontFamily:"var(--font-body)", fontSize:13, fontWeight:500, color:"var(--text-dim)", marginTop:5 }}>
            Live flow mirror — last 200 records
          </div>
        </div>
        <div style={{ display:"flex", gap:10, alignItems:"center" }}>
          {[
            { key:"all",    label:`All (${rows.length})`,       color:"#00d4ff" },
            { key:"attack", label:`Attacks (${counts.attack})`, color:"#ff2d55" },
            { key:"normal", label:`Normal (${counts.normal})`,  color:"#00ff88" },
          ].map(f => (
            <button key={f.key} onClick={() => setFilter(f.key)} style={{
              background:    filter===f.key ? `${f.color}18` : "transparent",
              border:        `1px solid ${filter===f.key ? f.color : "var(--border-dim)"}`,
              color:         filter===f.key ? f.color : "var(--text-dim)",
              fontFamily:    "var(--font-body)", fontSize:13, fontWeight:600,
              padding:       "7px 16px", borderRadius:5, cursor:"pointer",
            }}>{f.label}</button>
          ))}
          <button onClick={() => setPaused(p => !p)} style={{
            background:    paused ? "rgba(255,184,0,0.12)" : "transparent",
            border:        `1px solid ${paused ? "#ffb800" : "var(--border-dim)"}`,
            color:         paused ? "#ffb800" : "var(--text-dim)",
            fontFamily:    "var(--font-body)", fontSize:13, fontWeight:600,
            padding:       "7px 16px", borderRadius:5, cursor:"pointer",
          }}>{paused ? "⏵ Resume" : "⏸ Pause"}</button>
        </div>
      </div>

      <ProtocolBar rows={rows} />

      {/* Table */}
      <div style={{ background:"var(--bg-card)", border:"1px solid var(--border-dim)", borderRadius:8, overflow:"hidden", marginTop:20 }}>
        <div style={{ overflowX:"auto", maxHeight:540, overflowY:"auto" }}>
          <table style={{ width:"100%", borderCollapse:"collapse" }}>
            <thead>
              <tr>
                {["Time","Decision","Confidence","Z-Score","Pkt Rate","Byte Rate","Src Bytes","Pkts","Proto","Duration"]
                  .map(h => <th key={h} style={th}>{h}</th>)}
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr><td colSpan={10} style={{ ...td, textAlign:"center", padding:52, color:"var(--text-dim)", fontFamily:"var(--font-body)", fontSize:14 }}>
                  Waiting for data...
                </td></tr>
              ) : filtered.map((row,i) => (
                <FlowRow key={`${row.timestamp}-${i}`} row={row} index={i} />
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}