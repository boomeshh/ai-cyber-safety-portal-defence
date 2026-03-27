function Dashboard() {
  const user = JSON.parse(localStorage.getItem("user"));

  if (!user) {
    window.location.href = "/";
    return null;
  }

  return (
    <div className="dashboard-page">
      <div className="dashboard-box">
        <h1>Welcome, {user.full_name}</h1>
        <p>
          You are logged in to Rakshak AI. From here, you can submit complaints,
          track complaint status, and access your cyber safety tools.
        </p>

        <div className="dashboard-actions">
          <div className="action-card">
            <h3>Submit Complaint</h3>
            <p>
              Report suspicious messages, URLs, impersonation attempts, or cyber fraud.
            </p>
            <button className="btn" onClick={() => (window.location.href = "/submit")}>
              Open Complaint Form
            </button>
          </div>

          <div className="action-card">
            <h3>My Complaints</h3>
            <p>
              View all your submitted complaints and check their current review status.
            </p>
            <button className="btn" onClick={() => (window.location.href = "/my-complaints")}>
              View My Complaints
            </button>
          </div>
        </div>

        <button
          className="btn logout-btn"
          onClick={() => {
            localStorage.removeItem("user");
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