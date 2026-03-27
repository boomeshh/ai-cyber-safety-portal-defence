import { useState } from "react";

function SubmitComplaint() {
  const user = JSON.parse(localStorage.getItem("user"));

  const [form, setForm] = useState({
    category: "",
    complaint_text: "",
    suspicious_url: "",
    screenshot: null,
  });

  if (!user) {
    window.location.href = "/";
    return null;
  }

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      const formData = new FormData();
      formData.append("user_id", user.id);
      formData.append("user_name", user.full_name);
      formData.append("category", form.category);
      formData.append("complaint_text", form.complaint_text);
      formData.append("suspicious_url", form.suspicious_url);

      if (form.screenshot) {
        formData.append("screenshot", form.screenshot);
      }

      const res = await fetch("http://127.0.0.1:8000/complaints", {
        method: "POST",
        body: formData,
      });

      const data = await res.json();

      if (data.success) {
        alert(
          `Complaint Submitted Successfully!

Complaint ID: ${data.complaint_id}
Risk Level: ${data.risk_level}
Threat Type: ${data.threat_type}

Why Flagged:
${data.ai_reason}

Mitigation:
${data.mitigation}`
        );

        window.location.href = "/my-complaints";
      } else {
        alert(data.message || "Submission failed");
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
          unknown messages, or financial fraud.
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
            onChange={(e) =>
              setForm({ ...form, complaint_text: e.target.value })
            }
            required
          />

          <input
            type="text"
            placeholder="Suspicious URL (optional)"
            value={form.suspicious_url}
            onChange={(e) =>
              setForm({ ...form, suspicious_url: e.target.value })
            }
          />

          <input
            type="file"
            onChange={(e) =>
              setForm({ ...form, screenshot: e.target.files[0] })
            }
          />

          <button className="btn" type="submit">
            Submit Complaint
          </button>
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