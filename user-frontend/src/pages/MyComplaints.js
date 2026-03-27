import { useEffect, useState } from "react";

function getRiskBadgeClass(level) {
  switch (level) {
    case "Critical":
      return "badge-critical";
    case "High":
      return "badge-high";
    case "Medium":
      return "badge-medium";
    default:
      return "badge-low";
  }
}

function MyComplaints() {
  const user = JSON.parse(localStorage.getItem("user"));
  const [complaints, setComplaints] = useState([]);

  useEffect(() => {
    if (!user) {
      window.location.href = "/";
      return;
    }

    fetch(`http://127.0.0.1:8000/my-complaints/${user.id}`)
      .then((res) => res.json())
      .then((data) => setComplaints(data))
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
            {complaints.map((item) => (
              <div className="complaint-card" key={item.id}>
                <div className="complaint-top">
                  <h3>{item.id}</h3>
                  <span className={`risk-badge ${getRiskBadgeClass(item.risk_level)}`}>
                    {item.risk_level}
                  </span>
                </div>

                <p><strong>Category:</strong> {item.category}</p>
                <p><strong>Threat Type:</strong> {item.threat_type}</p>
                <p><strong>Risk Score:</strong> {item.risk_score}</p>
                <p><strong>Status:</strong> {item.status}</p>
                <p><strong>Date:</strong> {item.created_at}</p>

                <div className="complaint-section">
                  <strong>AI Reason:</strong>
                  <p>{item.ai_reason}</p>
                </div>

                <div className="complaint-section">
                  <strong>Mitigation:</strong>
                  <p>{item.mitigation}</p>
                </div>
              </div>
            ))}
          </div>
        )}

        <button
          className="btn"
          style={{ marginTop: "20px", background: "#334155" }}
          onClick={() => (window.location.href = "/dashboard")}
        >
          Back to Dashboard
        </button>
      </div>
    </div>
  );
}

export default MyComplaints;