import { useState } from "react";
import { getAuthHeaders, getStoredUser } from "../utils/auth";

const API = process.env.REACT_APP_API_BASE_URL || "https://ai-cyber-safety-portal-defence.onrender.com";

function SubmitComplaint() {
  const user = getStoredUser();

  const [form, setForm] = useState({
    category: "",
    complaint_text: "",
    suspicious_url: "",
    evidence: null,
  });

  if (!user) {
    window.location.href = "/";
    return null;
  }

  const evidenceName = form.evidence ? form.evidence.name : "";

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      const formData = new FormData();
      formData.append("user_id", user.id);
      formData.append("user_name", user.full_name);
      formData.append("category", form.category);
      formData.append("complaint_text", form.complaint_text);
      formData.append("suspicious_url", form.suspicious_url);
      if (form.evidence) {
        formData.append("evidence", form.evidence);
      }

      const res = await fetch(`${API}/complaints`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: formData,
      });

      const data = await res.json();

      if (data.success) {
        alert(`Complaint Submitted Successfully!\n\nComplaint ID: ${data.complaint_id}\nRisk Level: ${data.risk_level}\nThreat Type: ${data.threat_type}\nAI Confidence: ${data.ai_confidence}%\nCase Status: ${data.status}\nAttack Channel: ${data.attack_channel}\nLinked Cases: ${data.linked_case_count}\n\nWhy Flagged:\n${data.ai_reason}\n\nMitigation:\n${data.mitigation}`);
        window.location.href = "/my-complaints";
      } else {
        alert(data.message || data.detail || "Submission failed");
      }
    } catch (error) {
      alert("Complaint submission failed. Check backend connection.");
    }
  };

  return (
    <div className="dashboard-page">
      <div className="dashboard-box">
        <h1>Submit Complaint</h1>
        <p>
          Report suspicious cyber activity, fake links, impersonation attempts,
          unknown messages, risky attachments, audio scams, or fraud evidence.
        </p>

        <form className="form" onSubmit={handleSubmit}>
          <select
            value={form.category}
            onChange={(e) => setForm({ ...form, category: e.target.value })}
            required
          >
            <option value="">Select Category</option>
            <option>Serving Personnel</option>
            <option>Family Member</option>
            <option>Veteran</option>
          </select>

          <textarea
            rows="6"
            placeholder="Describe the issue in detail"
            value={form.complaint_text}
            onChange={(e) => setForm({ ...form, complaint_text: e.target.value })}
            required
          />

          <input
            type="text"
            placeholder="Suspicious URL (optional)"
            value={form.suspicious_url}
            onChange={(e) => setForm({ ...form, suspicious_url: e.target.value })}
          />

          <input
            type="file"
            accept=".png,.jpg,.jpeg,.webp,.pdf,.doc,.docx,.txt,.csv,.mp3,.wav,.m4a,.mp4,.mov,.avi,.apk,.zip"
            onChange={(e) => setForm({ ...form, evidence: e.target.files?.[0] || null })}
          />

          {evidenceName && <p style={{ marginTop: -6, fontSize: 14 }}>Selected evidence: {evidenceName}</p>}

          <button className="btn" type="submit">Submit Complaint</button>
        </form>

        <button
          className="btn"
          style={{ marginTop: "16px", background: "#334155" }}
          onClick={() => (window.location.href = "/dashboard")}
        >
          Back to Dashboard
        </button>
      </div>
    </div>
  );
}

export default SubmitComplaint;
