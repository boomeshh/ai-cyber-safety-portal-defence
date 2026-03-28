import { useEffect, useState } from "react";
import { getAuthHeaders, getStoredUser } from "../utils/auth";

const API = "http://127.0.0.1:8000";

function getRiskBadgeClass(level) {
  switch (level) {
    case "Critical": return "badge-critical";
    case "High": return "badge-high";
    case "Medium": return "badge-medium";
    default: return "badge-low";
  }
}

function parseAiReason(text) {
  const [indicatorsPart, explanationPart, campaignPart] = (text || "").split(/\n\n/);
  const indicators = (indicatorsPart || "")
    .replace("Detected Indicators:\n", "")
    .split("\n")
    .map((item) => item.replace(/^•\s*/, "").trim())
    .filter(Boolean);
  const explanation = (explanationPart || "").replace("Risk Explanation:\n", "").trim();
  const campaign = (campaignPart || "").replace("Campaign Alert:\n", "").trim();
  return { indicators, explanation, campaign };
}

function EvidencePreview({ complaintId }) {
  const [meta, setMeta] = useState(null);
  useEffect(() => {
    fetch(`${API}/complaints/${complaintId}/evidence-meta`, { headers: getAuthHeaders() })
      .then((res) => res.json())
      .then((data) => setMeta(data))
      .catch(() => setMeta({ available: false }));
  }, [complaintId]);

  if (!meta) return <p style={{ color: "#94a3b8" }}>Loading evidence info...</p>;
  if (!meta.available) return <p style={{ color: "#94a3b8" }}>No evidence attached.</p>;

  const src = `${API}/complaints/${complaintId}/evidence`;
  const headersNote = "Download will work using your current logged-in session in the app.";

  return (
    <div className="evidence-box">
      <div className="evidence-header">
        <strong>Evidence:</strong>
        <a className="mini-link" href={src} target="_blank" rel="noreferrer">Open / Download</a>
      </div>
      <p style={{ color: "#94a3b8", marginBottom: 10 }}>{meta.file_name}</p>
      {meta.file_type?.startsWith("image/") ? <img src={src} alt={meta.file_name} className="evidence-image" /> : null}
      {meta.file_type === "application/pdf" ? <iframe src={src} title={meta.file_name} className="evidence-frame" /> : null}
      {meta.file_type?.startsWith("audio/") ? <audio controls className="evidence-media"><source src={src} type={meta.file_type} /></audio> : null}
      {meta.file_type?.startsWith("video/") ? <video controls className="evidence-media"><source src={src} type={meta.file_type} /></video> : null}
      {!meta.file_type?.startsWith("image/") && meta.file_type !== "application/pdf" && !meta.file_type?.startsWith("audio/") && !meta.file_type?.startsWith("video/") ? (
        <p style={{ color: "#94a3b8" }}>{headersNote}</p>
      ) : null}
    </div>
  );
}

function MyComplaints() {
  const user = getStoredUser();
  const [complaints, setComplaints] = useState([]);

  useEffect(() => {
    if (!user) {
      window.location.href = "/";
      return;
    }
    fetch(`${API}/my-complaints/${user.id}`, { headers: getAuthHeaders() })
      .then((res) => res.json())
      .then((data) => setComplaints(Array.isArray(data) ? data : []))
      .catch(() => alert("Failed to load complaints"));
  }, [user]);

  if (!user) return null;

  return (
    <div className="dashboard-page">
      <div className="dashboard-box">
        <h1>My Complaints</h1>
        <p>Track all complaints submitted by your account.</p>

        {complaints.length === 0 ? (
          <div className="empty-box">
            <h3>No complaints found</h3>
            <p>You have not submitted any complaints yet.</p>
          </div>
        ) : (
          <div className="complaints-grid">
            {complaints.map((item) => {
              const parsed = parseAiReason(item.ai_reason);
              return (
                <div className="complaint-card" key={item.id}>
                  <div className="complaint-top">
                    <h3>{item.id}</h3>
                    <span className={`risk-badge ${getRiskBadgeClass(item.risk_level)}`}>{item.risk_level}</span>
                  </div>

                  {Number(item.linked_case_count || 0) > 0 ? (
                    <div className="campaign-alert">⚠ Potential campaign attack: linked with {item.linked_case_count} earlier case(s).</div>
                  ) : null}

                  <p><strong>Category:</strong> {item.category}</p>
                  <p><strong>Threat Type:</strong> {item.threat_type}</p>
                  <p><strong>Risk Score:</strong> {item.risk_score}</p>
                  <p><strong>AI Confidence:</strong> {item.ai_confidence || 0}%</p>
                  <p><strong>Status:</strong> {item.status}</p>
                  <p><strong>Channel:</strong> {item.attack_channel || "Unknown"}</p>
                  <p><strong>Linked Cases:</strong> {item.linked_case_count || 0}</p>
                  <p><strong>Date:</strong> {item.created_at}</p>

                  <div className="complaint-section">
                    <strong>Detected Indicators</strong>
                    <ul className="indicator-list">
                      {parsed.indicators.map((indicator) => <li key={indicator}>{indicator}</li>)}
                    </ul>
                  </div>

                  <div className="complaint-section">
                    <strong>Risk Explanation</strong>
                    <p>{parsed.explanation || item.ai_reason}</p>
                  </div>

                  {parsed.campaign ? (
                    <div className="complaint-section">
                      <strong>Campaign Alert</strong>
                      <p>{parsed.campaign}</p>
                    </div>
                  ) : null}

                  <div className="complaint-section">
                    <strong>Mitigation</strong>
                    <p>{item.mitigation}</p>
                  </div>

                  <div className="complaint-section">
                    <EvidencePreview complaintId={item.id} />
                  </div>
                </div>
              );
            })}
          </div>
        )}

        <button className="btn" style={{ marginTop: "20px", background: "#334155" }} onClick={() => (window.location.href = "/dashboard")}>
          Back to Dashboard
        </button>
      </div>
    </div>
  );
}

export default MyComplaints;
