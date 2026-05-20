import { useState } from "react";
import { getAuthHeaders, getStoredUser } from "../utils/auth";

const API = process.env.REACT_APP_API_BASE_URL || "https://ai-cyber-safety-portal-defence.onrender.com";

const CATEGORIES = ["Serving Personnel", "Family Member", "Veteran"];

function SubmitComplaint() {
  const user = getStoredUser();
  const [form, setForm] = useState({ category: "", complaint_text: "", suspicious_url: "", evidence: null });
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  if (!user) { window.location.href = "/"; return null; }

  const evidenceName = form.evidence ? form.evidence.name : "";

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(""); setResult(null); setLoading(true);

    try {
      const formData = new FormData();
      formData.append("user_id", user.id);
      formData.append("user_name", user.full_name);
      formData.append("category", form.category);
      formData.append("complaint_text", form.complaint_text);
      formData.append("suspicious_url", form.suspicious_url);
      if (form.evidence) formData.append("evidence", form.evidence);

      const res = await fetch(`${API}/complaints`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: formData,
      });
      const data = await res.json();

      if (data.success) {
        setResult(data);
        setForm({ category: "", complaint_text: "", suspicious_url: "", evidence: null });
      } else {
        setError(data.message || data.detail || "Submission failed. Please try again.");
      }
    } catch {
      setError("Complaint submission failed. Check backend connection.");
    } finally {
      setLoading(false);
    }
  };

  const riskColor = { Critical: "#ef4444", High: "#f97316", Medium: "#eab308", Low: "#22c55e" };

  return (
    <div className="dashboard-page">
      <div className="dashboard-box">

        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6, flexWrap: 'wrap', gap: 12 }}>
          <h1>Submit Complaint</h1>
          <button className="btn" style={{ background: '#1e293b', padding: '9px 16px', fontSize: '0.85rem' }}
            onClick={() => window.location.href = "/dashboard"}>
            ← Dashboard
          </button>
        </div>
        <p>Report suspicious cyber activity with evidence. AI will analyze and classify the threat in real time.</p>

        {/* Success Result */}
        {result && (
          <div style={{
            marginBottom: 24, padding: 20,
            background: 'rgba(13,27,46,0.9)',
            border: `1px solid ${riskColor[result.risk_level] || '#334155'}`,
            borderRadius: 16,
            animation: 'fadeSlideUp 0.3s ease both',
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14, flexWrap: 'wrap', gap: 10 }}>
              <div>
                <div style={{ fontSize: 11, color: '#64748b', letterSpacing: '1px', textTransform: 'uppercase', marginBottom: 4 }}>Complaint Registered</div>
                <div style={{ fontFamily: 'Courier New, monospace', color: '#38bdf8', fontWeight: 700, fontSize: '1rem' }}>{result.complaint_id}</div>
              </div>
              <span className={`risk-badge badge-${result.risk_level?.toLowerCase()}`}>
                {result.risk_level} · {result.risk_score}/100
              </span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: 10, marginBottom: 14 }}>
              {[
                ['Threat Type', result.threat_type],
                ['AI Confidence', `${result.ai_confidence}%`],
                ['Status', result.status],
                ['Channel', result.attack_channel],
              ].map(([label, val]) => (
                <div key={label} style={{ background: 'rgba(2,8,23,0.5)', borderRadius: 10, padding: '10px 14px' }}>
                  <div style={{ fontSize: 11, color: '#64748b', marginBottom: 3 }}>{label}</div>
                  <div style={{ color: '#e2e8f0', fontWeight: 600, fontSize: '0.9rem' }}>{val}</div>
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              <button className="btn" style={{ fontSize: '0.85rem', padding: '9px 16px' }}
                onClick={() => window.location.href = "/my-complaints"}>
                View My Cases →
              </button>
              <button className="btn" style={{ background: '#1e293b', fontSize: '0.85rem', padding: '9px 16px' }}
                onClick={() => setResult(null)}>
                Submit Another
              </button>
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="alert-banner error" style={{ marginBottom: 18 }}>
            <span>⚠</span> {error}
          </div>
        )}

        {/* Form */}
        {!result && (
          <form className="form" onSubmit={handleSubmit}>
            <div>
              <label style={{ fontSize: 12, color: '#64748b', letterSpacing: '0.5px', textTransform: 'uppercase', display: 'block', marginBottom: 6 }}>
                Category *
              </label>
              <select value={form.category} onChange={(e) => setForm({ ...form, category: e.target.value })} required>
                <option value="">Select your category</option>
                {CATEGORIES.map(c => <option key={c}>{c}</option>)}
              </select>
            </div>

            <div>
              <label style={{ fontSize: 12, color: '#64748b', letterSpacing: '0.5px', textTransform: 'uppercase', display: 'block', marginBottom: 6 }}>
                Incident Description *
              </label>
              <textarea
                rows="6"
                placeholder="Describe the suspicious activity in detail — include message content, sender details, what happened, and any other relevant information..."
                value={form.complaint_text}
                onChange={(e) => setForm({ ...form, complaint_text: e.target.value })}
                required
              />
              <div style={{ textAlign: 'right', fontSize: 11, color: '#475569', marginTop: 4 }}>
                {form.complaint_text.length} characters
              </div>
            </div>

            <div>
              <label style={{ fontSize: 12, color: '#64748b', letterSpacing: '0.5px', textTransform: 'uppercase', display: 'block', marginBottom: 6 }}>
                Suspicious URL (optional)
              </label>
              <input
                type="text"
                placeholder="https://suspicious-link.example.com"
                value={form.suspicious_url}
                onChange={(e) => setForm({ ...form, suspicious_url: e.target.value })}
              />
            </div>

            <div>
              <label style={{ fontSize: 12, color: '#64748b', letterSpacing: '0.5px', textTransform: 'uppercase', display: 'block', marginBottom: 6 }}>
                Evidence Upload (optional)
              </label>
              <input
                type="file"
                accept=".png,.jpg,.jpeg,.webp,.pdf,.doc,.docx,.txt,.csv,.mp3,.wav,.m4a,.mp4,.mov,.avi,.apk,.zip"
                onChange={(e) => setForm({ ...form, evidence: e.target.files?.[0] || null })}
                style={{ cursor: 'pointer' }}
              />
              {evidenceName && (
                <div style={{ marginTop: 8, padding: '8px 12px', background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)', borderRadius: 8, fontSize: 13, color: '#4ade80' }}>
                  📎 {evidenceName}
                </div>
              )}
              <div style={{ marginTop: 6, fontSize: 11, color: '#475569' }}>
                Supported: Images, PDF, Audio, Video, APK, ZIP · Max 15 MB
              </div>
            </div>

            <button className="btn" type="submit" disabled={loading} style={{ marginTop: 8 }}>
              {loading ? <><span className="spinner" /> Analyzing threat...</> : "🚨 Submit for AI Analysis"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}

export default SubmitComplaint;
