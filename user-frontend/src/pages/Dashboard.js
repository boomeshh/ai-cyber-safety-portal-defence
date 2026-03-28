import { getStoredUser, logoutUser } from "../utils/auth";

function Dashboard() {
  const user = getStoredUser();

  if (!user) {
    window.location.href = "/";
    return null;
  }

  return (
    <div className="dashboard-page">
      <div className="dashboard-box">
        <h1>Welcome, {user.full_name}</h1>
        <p>
          You are logged in to Rakshak AI. Submit multi-format cyber complaints,
          view AI risk analysis, and track the case workflow securely.
        </p>

        <div className="dashboard-actions">
          <div className="action-card">
            <h3>Submit Complaint</h3>
            <p>
              Report suspicious messages, links, attachments, audio calls, videos,
              impersonation attempts, and cyber fraud.
            </p>
            <button className="btn" onClick={() => (window.location.href = "/submit")}>Open Complaint Form</button>
          </div>

          <div className="action-card">
            <h3>My Complaints</h3>
            <p>
              View your submitted complaints, AI confidence, linked indicators, and current case status.
            </p>
            <button className="btn" onClick={() => (window.location.href = "/my-complaints")}>View My Complaints</button>
          </div>
        </div>

        <button
          className="btn logout-btn"
          onClick={() => {
            logoutUser();
            window.location.href = "/";
          }}
        >
          Logout
        </button>
      </div>
    </div>
  );
}

export default Dashboard;
