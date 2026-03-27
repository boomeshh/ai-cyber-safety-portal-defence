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

function AdminDashboard() {
  const [analytics, setAnalytics] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    open_cases: 0,
    escalated: 0,
    resolved: 0,
  });

  const [complaints, setComplaints] = useState([]);

  const loadDashboardData = () => {
    fetch("http://127.0.0.1:8000/analytics")
      .then((res) => res.json())
      .then((data) => setAnalytics(data))
      .catch(() => alert("Failed to load analytics"));

    fetch("http://127.0.0.1:8000/complaints")
      .then((res) => res.json())
      .then((data) => setComplaints(data))
      .catch(() => alert("Failed to load complaints"));
  };

  useEffect(() => {
    loadDashboardData();
  }, []);

  const handleStatusChange = async (caseId, newStatus) => {
    try {
      const res = await fetch(
        `http://127.0.0.1:8000/update-status/${caseId}?status=${encodeURIComponent(newStatus)}`,
        {
          method: "PUT",
        }
      );

      const data = await res.json();

      if (data.success) {
        alert("Status updated successfully");
        loadDashboardData();
      } else {
        alert("Status update failed");
      }
    } catch (error) {
      alert("Backend connection failed while updating status");
    }
  };

  const criticalComplaints = complaints.filter(
    (item) => item.risk_level === "Critical"
  );

  return (
    <div className="admin-page">
      <div className="admin-shell">
        <div className="admin-header">
          <div>
            <h1>Rakshak AI Admin Dashboard</h1>
            <p>Monitor complaints, risk levels, live alerts, and case status updates.</p>
          </div>

          <button
            className="btn"
            onClick={() =>
              window.open("http://127.0.0.1:8000/download/excel", "_blank")
            }
          >
            Download Excel
          </button>
        </div>

        {criticalComplaints.length > 0 && (
          <div
            style={{
              background: "#dc2626",
              color: "white",
              padding: "14px 18px",
              borderRadius: "16px",
              marginBottom: "20px",
              fontWeight: "700",
              boxShadow: "0 8px 20px rgba(220,38,38,0.25)",
            }}
          >
            🚨 Critical Alert Detected — {criticalComplaints.length} high priority case(s) require immediate review.
          </div>
        )}

        <div className="admin-cards">
          <div className="admin-card">
            <h3>Total Complaints</h3>
            <h2>{analytics.total}</h2>
          </div>

          <div className="admin-card">
            <h3>Critical Alerts</h3>
            <h2>{analytics.critical}</h2>
          </div>

          <div className="admin-card">
            <h3>Open Cases</h3>
            <h2>{analytics.open_cases}</h2>
          </div>

          <div className="admin-card">
            <h3>Resolved</h3>
            <h2>{analytics.resolved}</h2>
          </div>
        </div>

        <div className="table-box">
          <h2>All Complaints</h2>

          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>User</th>
                  <th>Category</th>
                  <th>Threat</th>
                  <th>Risk Score</th>
                  <th>Risk Level</th>
                  <th>Status</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {complaints.map((item) => (
                  <tr key={item.id}>
                    <td>{item.id}</td>
                    <td>{item.user_name}</td>
                    <td>{item.category}</td>
                    <td>{item.threat_type}</td>
                    <td>{item.risk_score}</td>
                    <td>
                      <span className={`risk-badge ${getRiskBadgeClass(item.risk_level)}`}>
                        {item.risk_level}
                      </span>
                    </td>
                    <td>
                      <select
                        value={item.status}
                        onChange={(e) => handleStatusChange(item.id, e.target.value)}
                        style={{
                          background: "#111827",
                          color: "white",
                          border: "1px solid #334155",
                          borderRadius: "10px",
                          padding: "8px 10px",
                        }}
                      >
                        <option value="Open">Open</option>
                        <option value="Under Review">Under Review</option>
                        <option value="Escalated">Escalated</option>
                        <option value="Resolved">Resolved</option>
                      </select>
                    </td>
                    <td>{item.created_at}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}

export default AdminDashboard;