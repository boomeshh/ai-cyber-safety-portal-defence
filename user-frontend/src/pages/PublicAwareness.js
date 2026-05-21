import { useEffect, useState } from "react";

const API = process.env.REACT_APP_API_BASE_URL || "https://ai-cyber-safety-portal-defence.onrender.com";

export default function PublicAwareness() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    fetch(`${API}/public/awareness`)
      .then((r) => r.json())
      .then(setData)
      .catch(() => setError("Failed to load awareness data."));
  }, []);

  if (error) return <div className="page"><div className="card"><p style={{ color: "#fca5a5" }}>{error}</p></div></div>;
  if (!data) return <div className="page"><div className="card"><p style={{ color: "#94a3b8" }}>Loading...</p></div></div>;

  return (
    <div className="page" style={{ minHeight: "100vh", padding: "28px 16px", alignItems: "flex-start" }}>
      <div style={{ maxWidth: 800, width: "100%", margin: "0 auto" }}>
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <h1 style={{ color: "#f8fafc", fontSize: "1.8rem" }}>Rakshak AI</h1>
          <p style={{ color: "#94a3b8" }}>Cyber Threat Awareness Dashboard — Anonymized Public Statistics</p>
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 16, marginBottom: 28 }}>
          <StatCard label="Total Reports" value={data.total_reports} />
          <StatCard label="Critical Cases" value={data.risk_distribution?.Critical || 0} color="#ef4444" />
          <StatCard label="High Risk" value={data.risk_distribution?.High || 0} color="#f97316" />
          <StatCard label="Resolved" value={data.status_distribution?.Resolved || 0} color="#22c55e" />
        </div>

        <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 16, marginBottom: 28 }}>
          <Panel title="Top Threat Types">
            {data.top_threat_types.map((t, i) => (
              <BarRow key={i} label={t.type} value={t.count} max={data.top_threat_types[0]?.count || 1} />
            ))}
          </Panel>
          <Panel title="Top Attack Channels">
            {data.top_channels.map((c, i) => (
              <BarRow key={i} label={c.channel} value={c.count} max={data.top_channels[0]?.count || 1} />
            ))}
          </Panel>
        </div>

        <Panel title="Risk Distribution">
          <div style={{ display: "flex", gap: 12, flexWrap: "wrap" }}>
            {Object.entries(data.risk_distribution).map(([level, count]) => (
              <div key={level} style={{ background: "#1e293b", borderRadius: 10, padding: "10px 18px", textAlign: "center" }}>
                <div style={{ color: riskColor(level), fontWeight: 700, fontSize: "1.2rem" }}>{count}</div>
                <div style={{ color: "#94a3b8", fontSize: 12 }}>{level}</div>
              </div>
            ))}
          </div>
        </Panel>

        <p style={{ color: "#475569", fontSize: 12, textAlign: "center", marginTop: 24 }}>
          {data.note} · Data updated in real time.
        </p>
      </div>
    </div>
  );
}

function StatCard({ label, value, color }) {
  return (
    <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 12, padding: "16px 20px", textAlign: "center" }}>
      <div style={{ color: color || "#38bdf8", fontWeight: 800, fontSize: "1.6rem" }}>{value ?? 0}</div>
      <div style={{ color: "#94a3b8", fontSize: 13 }}>{label}</div>
    </div>
  );
}

function Panel({ title, children }) {
  return (
    <div style={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 12, padding: 20 }}>
      <div style={{ color: "#e2e8f0", fontWeight: 700, marginBottom: 14 }}>{title}</div>
      {children}
    </div>
  );
}

function BarRow({ label, value, max }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0;
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: "flex", justifyContent: "space-between", color: "#cbd5e1", fontSize: 13, marginBottom: 4 }}>
        <span>{label}</span><span>{value}</span>
      </div>
      <div style={{ background: "#1e293b", borderRadius: 4, height: 6 }}>
        <div style={{ background: "#38bdf8", borderRadius: 4, height: 6, width: `${pct}%` }} />
      </div>
    </div>
  );
}

function riskColor(level) {
  return { Critical: "#ef4444", High: "#f97316", Medium: "#eab308", Low: "#22c55e" }[level] || "#94a3b8";
}
