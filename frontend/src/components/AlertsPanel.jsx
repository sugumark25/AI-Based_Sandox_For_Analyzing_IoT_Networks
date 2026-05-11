import { useState, useEffect } from "react";
import { fetchRecent } from "../services/api";

const REFRESH_MS = 3000;

function SeverityBadge({ z, conf }) {
  const sv =
    z>=4||conf>=0.95 ? { label:"Critical", color:"#ff2d55" } :
    z>=2||conf>=0.80 ? { label:"High",     color:"#ffb800" } :
    z>=1||conf>=0.60 ? { label:"Medium",   color:"#00d4ff" } :
                       { label:"Low",       color:"#9d4edd" };
  return (
    <span style={{
      fontFamily:    "var(--font-body)", fontSize:12, fontWeight:700,
      color:         sv.color, background:`${sv.color}18`,
      border:        `1px solid ${sv.color}44`,
      padding:       "3px 12px", borderRadius:4,
      textShadow:    `0 0 8px ${sv.color}`,
      animation:     sv.label==="Critical" ? "pulse-glow 1s ease infinite" : "none",
    }}>{sv.label}</span>
  );
}

function AlertCard({ attack, index }) {
  const z     = parseFloat(attack.z_score        || 0);
  const conf  = parseFloat(attack.edge_confidence || 0);
  const proto = attack.proto_tcp==1?"TCP":attack.proto_udp==1?"UDP":attack.proto_icmp==1?"ICMP":"?";

  return (
    <div style={{
      background:   "var(--bg-card)", border:"1px solid rgba(255,45,85,0.2)",
      borderLeft:   "4px solid #ff2d55", borderRadius:8,
      padding:      "20px 24px", marginBottom:14,
      animation:    index===0 ? "slide-in 0.3s ease" : "none",
      boxShadow:    "0 2px 16px rgba(255,45,85,0.08)",
    }}>
      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:16 }}>
        <div style={{ display:"flex", alignItems:"center", gap:12 }}>
          <span style={{ color:"#ff2d55", animation:"pulse-glow 2s ease infinite", fontSize:18 }}>⚠</span>
          <span style={{ fontFamily:"var(--font-display)", fontSize:15, fontWeight:700, color:"var(--text-primary)", letterSpacing:1 }}>
            Attack Detected
          </span>
          <SeverityBadge z={z} conf={conf} />
        </div>
        <span style={{ fontFamily:"var(--font-mono)", fontSize:12, color:"var(--text-dim)" }}>
          {attack.timestamp?.slice(11,23)}
        </span>
      </div>

      <div style={{ display:"grid", gridTemplateColumns:"repeat(auto-fit, minmax(140px, 1fr))", gap:12 }}>
        {[
          ["Confidence", `${(conf*100).toFixed(1)}%`,                      "#ff2d55"],
          ["Z-Score",    z.toFixed(3),                                      z>=2?"#ffb800":"#00d4ff"],
          ["Protocol",   proto,                                              "#00d4ff"],
          ["Src Bytes",  parseFloat(attack.src_bytes  ||0).toLocaleString(),"#9d4edd"],
          ["Pkt Rate",   parseFloat(attack.packet_rate||0).toFixed(1),      "#00ff88"],
          ["Byte Rate",  parseFloat(attack.byte_rate  ||0).toFixed(0),      "#ffb800"],
          ["Duration",   `${parseFloat(attack.duration||0).toFixed(3)}s`,   "#00d4ff"],
          ["Device",     attack.device_id ?? "--",                           "#9d4edd"],
        ].map(([l,v,c]) => (
          <div key={l} style={{ background:"rgba(255,255,255,0.02)", borderRadius:6, padding:"10px 14px", border:"1px solid var(--border-dim)" }}>
            <div style={{ fontFamily:"var(--font-body)", fontSize:11, fontWeight:700, color:"var(--text-dim)", textTransform:"uppercase", letterSpacing:0.8, marginBottom:6 }}>{l}</div>
            <div style={{ fontFamily:"var(--font-mono)", fontSize:14, fontWeight:600, color:c }}>{v}</div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function AlertsPanel() {
  const [attacks, setAttacks] = useState([]);
  const [paused,  setPaused]  = useState(false);

  async function load() {
    if (paused) return;
    try {
      const data = await fetchRecent(200);
      setAttacks(data.filter(r=>r.edge_decision==="attack").reverse());
    } catch {}
  }

  useEffect(() => { load(); const t = setInterval(load, REFRESH_MS); return () => clearInterval(t); }, [paused]);

  const critical = attacks.filter(a=>parseFloat(a.z_score||0)>=4||parseFloat(a.edge_confidence||0)>=0.95).length;
  const high     = attacks.filter(a=>{const z=parseFloat(a.z_score||0),c=parseFloat(a.edge_confidence||0);return(z>=2||c>=0.8)&&!(z>=4||c>=0.95);}).length;

  return (
    <div style={{ padding:"30px 34px", position:"relative", zIndex:1 }}>

      {/* Header */}
      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:26 }}>
        <div>
          <div style={{ fontFamily:"var(--font-display)", fontSize:28, fontWeight:800, color:"#ff2d55", letterSpacing:2, animation:attacks.length>0?"pulse-glow 2s ease infinite":"none" }}>
            Alerts
          </div>
          <div style={{ fontFamily:"var(--font-body)", fontSize:13, fontWeight:500, color:"var(--text-dim)", marginTop:5 }}>
            Attack events — backend verified only
          </div>
        </div>
        <div style={{ display:"flex", gap:12, alignItems:"center" }}>
          <div style={{ fontFamily:"var(--font-body)", fontSize:13, fontWeight:600, color:"#ff2d55", background:"rgba(255,45,85,0.1)", border:"1px solid rgba(255,45,85,0.3)", padding:"6px 16px", borderRadius:5 }}>
            {attacks.length} total · {critical} critical · {high} high
          </div>
          <button onClick={() => setPaused(p=>!p)} style={{
            background:    paused?"rgba(255,184,0,0.12)":"transparent",
            border:        `1px solid ${paused?"#ffb800":"var(--border-dim)"}`,
            color:         paused?"#ffb800":"var(--text-dim)",
            fontFamily:    "var(--font-body)", fontSize:13, fontWeight:600,
            padding:       "6px 16px", borderRadius:5, cursor:"pointer",
          }}>{paused?"⏵ Resume":"⏸ Pause"}</button>
        </div>
      </div>

      {/* Summary */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:16, marginBottom:26 }}>
        {[
          ["Critical", critical,                         "#ff2d55","Z ≥ 4 or conf ≥ 95%"],
          ["High",     high,                             "#ffb800","Z ≥ 2 or conf ≥ 80%"],
          ["Medium",   attacks.length-critical-high,    "#00d4ff","Z ≥ 1 or conf ≥ 60%"],
          ["Total",    attacks.length,                  "#9d4edd","All verified attacks"],
        ].map(([l,v,c,sub]) => (
          <div key={l} style={{ background:"var(--bg-card)", border:`1px solid ${c}33`, borderTop:`3px solid ${c}`, borderRadius:8, padding:"20px 22px" }}>
            <div style={{ fontFamily:"var(--font-body)", fontSize:12, fontWeight:700, color:"var(--text-dim)", textTransform:"uppercase", letterSpacing:1, marginBottom:10 }}>{l}</div>
            <div style={{ fontFamily:"var(--font-display)", fontSize:30, fontWeight:800, color:c, textShadow:`0 0 12px ${c}66`, animation:l==="Critical"&&v>0?"pulse-glow 1.5s ease infinite":"none" }}>{v}</div>
            <div style={{ fontFamily:"var(--font-body)", fontSize:12, fontWeight:500, color:"var(--text-dim)", marginTop:8 }}>{sub}</div>
          </div>
        ))}
      </div>

      {/* Alert cards */}
      <div style={{ maxHeight:560, overflowY:"auto", paddingRight:4 }}>
        {attacks.length===0 ? (
          <div style={{ background:"var(--bg-card)", border:"1px solid var(--border-dim)", borderRadius:8, padding:56, textAlign:"center" }}>
            <div style={{ fontFamily:"var(--font-display)", fontSize:18, fontWeight:700, color:"#00ff88" }}>
              ✓ No Attacks Detected
            </div>
            <div style={{ fontFamily:"var(--font-body)", fontSize:14, fontWeight:500, color:"var(--text-dim)", marginTop:12 }}>
              Backend is clean — edge cache blocking repeated patterns
            </div>
          </div>
        ) : attacks.map((a,i) => <AlertCard key={`${a.timestamp}-${i}`} attack={a} index={i} />)}
      </div>
    </div>
  );
}