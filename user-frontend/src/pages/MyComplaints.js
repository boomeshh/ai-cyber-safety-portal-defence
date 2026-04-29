import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { getAuthHeaders, getStoredUser } from "../utils/auth";

const API = "https://ai-cyber-safety-portal-defence.onrender.com";

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
  const [fileUrl, setFileUrl] = useState("");
  const [error, setError] = useState("");
  const objectUrlRef = useRef("");

  useEffect(() => {
    let cancelled = false;

    const loadEvidence = async () => {
      try {
        const metaRes = await fetch(`${API}/complaints/${complaintId}/evidence-meta`, {
          headers: getAuthHeaders(),
        });
        const metaData = await metaRes.json();
        if (!metaRes.ok) throw new Error(metaData.detail || "Failed to load evidence info");
        if (cancelled) return;
        setMeta(metaData);

        if (!metaData.available) return;

        const fileRes = await fetch(`${API}/complaints/${complaintId}/evidence`, {
          headers: getAuthHeaders(),
        });
        if (!fileRes.ok) {
          let message = "Failed to load evidence file";
          try {
            const err = await fileRes.json();
            message = err.detail || message;
          } catch {}
          throw new Error(message);
        }

        const blob = await fileRes.blob();
        const url = URL.createObjectURL(blob);
        objectUrlRef.current = url;
        if (!cancelled) setFileUrl(url);
      } catch (err) {
        if (!cancelled) setError(err.message || "Failed to load evidence");
      }
    };

    loadEvidence();

    return () => {
      cancelled = true;
      if (objectUrlRef.current) URL.revokeObjectURL(objectUrlRef.current);
    };
  }, [complaintId]);

  const handleDownload = () => {
    if (!fileUrl || !meta?.file_name) return;
    const a = document.createElement("a");
    a.href = fileUrl;
    a.download = meta.file_name;
    document.body.appendChild(a);
    a.click();
    a.remove();
  };

  if (error) return <p style={{ color: "#fca5a5" }}>{error}</p>;
  if (!meta) return <p style={{ color: "#94a3b8" }}>Loading evidence info...</p>;
  if (!meta.available) return <p style={{ color: "#94a3b8" }}>No evidence attached.</p>;
  if (!fileUrl) return <p style={{ color: "#94a3b8" }}>Loading evidence preview...</p>;

  return (
    <div className="evidence-box">
      <div className="evidence-header">
        <strong>Evidence:</strong>
        <button type="button" className="btn" style={{ padding: "8px 12px", fontSize: 14 }} onClick={handleDownload}>
          Download Evidence
        </button>
      </div>
      <p style={{ color: "#94a3b8", marginBottom: 10 }}>{meta.file_name}</p>
      {meta.file_type?.startsWith("image/") ? <img src={fileUrl} alt={meta.file_name} className="evidence-image" /> : null}
      {meta.file_type === "application/pdf" ? <iframe src={fileUrl} title={meta.file_name} className="evidence-frame" /> : null}
      {meta.file_type?.startsWith("audio/") ? <audio controls className="evidence-media"><source src={fileUrl} type={meta.file_type} /></audio> : null}
      {meta.file_type?.startsWith("video/") ? <video controls className="evidence-media"><source src={fileUrl} type={meta.file_type} /></video> : null}
      {!meta.file_type?.startsWith("image/") && meta.file_type !== "application/pdf" && !meta.file_type?.startsWith("audio/") && !meta.file_type?.startsWith("video/") ? (
        <p style={{ color: "#94a3b8" }}>Preview is not available for this file type. Use download button.</p>
      ) : null}
    </div>
  );
}

function MyComplaints() {
  const navigate = useNavigate();
  const user = getStoredUser();
  const [complaints, setComplaints] = useState([]);

  useEffect(() => {
    const loadComplaints = async () => {
      if (!user) {
        navigate("/");
        return;
      }

      try {
        const res = await fetch(`${API}/my-complaints/${user.id}`, { headers: getAuthHeaders() });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || "Failed to load complaints");
        setComplaints(Array.isArray(data) ? data : []);
      } catch (err) {
        alert(err.message || "Failed to load complaints");
      }
    };

    loadComplaints();
  }, [navigate, user]);

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
                      {parsed.indicators.map((indicator, index) => <li key={`${item.id}-${index}`}>{indicator}</li>)}
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

        <button className="btn" style={{ marginTop: "20px", background: "#334155" }} onClick={() => navigate("/dashboard")}>
          Back to Dashboard
        </button>
      </div>
    </div>
  );
}

export default MyComplaints;
