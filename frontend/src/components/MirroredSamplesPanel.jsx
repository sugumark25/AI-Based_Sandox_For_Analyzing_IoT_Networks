import { useEffect, useState } from "react";
import { fetchMirrors, onBridgeEvent } from "../services/api";

export default function MirroredSamplesPanel() {
  const [samples, setSamples] = useState([]);

  useEffect(() => {
    let mounted = true;
    fetchMirrors(50).then(r => {
      if (mounted) setSamples(r.samples || []);
    }).catch(() => {});

    const off = onBridgeEvent("mirrored_sample", (data) => {
      setSamples(s => [data, ...s].slice(0, 50));
    });

    return () => { mounted = false; off(); };
  }, []);

  return (
    <div style={{ padding: 20 }}>
      <h3>Mirrored Samples</h3>
      <div style={{ display: "grid", gap: 8 }}>
        {samples.map(s => (
          <div key={s.sample_id || s.id} style={{ padding: 12, border: "1px solid var(--border-mid)", borderRadius: 8 }}>
            <div style={{ fontWeight: 700 }}>{s.device_id} <span style={{ fontWeight: 500, color: "var(--text-dim)", marginLeft: 8 }}>{new Date(s.timestamp).toLocaleString()}</span></div>
            <div style={{ marginTop: 6 }}>Decision: <strong>{s.sandbox_decision}</strong> &nbsp; Score: {Number(s.sandbox_score).toFixed(3)}</div>
            <div style={{ marginTop: 6, fontSize: 12, color: "var(--text-dim)" }}>{s.src_ip} → {s.dst_ip} {s.proto ? `(${s.proto})` : ""}</div>
          </div>
        ))}
        {samples.length === 0 && <div style={{ color: "var(--text-dim)" }}>No mirrored samples yet.</div>}
      </div>
    </div>
  );
}
