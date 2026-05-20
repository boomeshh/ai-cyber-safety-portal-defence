import { useNavigate } from "react-router-dom";
import { getStoredUser, logoutUser } from "../utils/auth";

function Dashboard() {
  const navigate = useNavigate();
  const user = getStoredUser();

  if (!user) {
    navigate("/");
    return null;
  }

  const initials = (user.full_name || "U").split(" ").map(w => w[0]).join("").slice(0, 2).toUpperCase();

  return (
    <div className="dashboard-page">
      <div className="dashboard-box">

        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 28, flexWrap: 'wrap', gap: 16 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <div style={{
              width: 52, height: 52, borderRadius: 14,
              background: 'linear-gradient(135deg, rgba(34,197,94,0.2), rgba(56,189,248,0.15))',
              border: '1px solid rgba(34,197,94,0.3)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: '1.1rem', fontWeight: 800, color: '#4ade80', flexShrink: 0,
            }}>
              {initials}
            </div>
            <div>
              <h1 style={{ marginBottom: 2 }}>Welcome, {user.full_name}</h1>
              <p style={{ margin: 0, fontSize: 13 }}>
                <span className="status-dot online" />
                Authenticated · {user.role || "user"} · {user.email}
              </p>
            </div>
          </div>
          <button
            className="btn logout-btn"
            style={{ padding: '10px 18px', fontSize: '0.88rem' }}
            onClick={() => { logoutUser(); navigate("/"); }}
          >
            Sign Out
          </button>
        </div>

        <div className="divider" />

        {/* Kicker */}
        <div style={{ marginBottom: 20 }}>
          <span style={{ fontSize: 11, color: '#64748b', letterSpacing: '1.5px', textTransform: 'uppercase', fontWeight: 700 }}>
            YUDHISTHIRA · AI Cyber Defence Platform
          </span>
          <p style={{ marginTop: 6, color: '#94a3b8', fontSize: '0.9rem', marginBottom: 0 }}>
            Submit multi-format cyber complaints, view AI risk analysis, and track case workflows securely.
          </p>
        </div>

        {/* Action Cards */}
        <div className="dashboard-actions">
          <div className="action-card">
            <div style={{ fontSize: '1.6rem', marginBottom: 12 }}>📋</div>
            <h3>Submit Complaint</h3>
            <p>
              Report suspicious messages, fake links, APK threats, impersonation attempts,
              audio scams, and cyber fraud with evidence upload.
            </p>
            <button className="btn" onClick={() => navigate("/submit")}>
              Open Complaint Form →
            </button>
          </div>

          <div className="action-card">
            <div style={{ fontSize: '1.6rem', marginBottom: 12 }}>🔍</div>
            <h3>My Complaints</h3>
            <p>
              View submitted complaints, AI threat analysis, confidence scores,
              linked campaign indicators, and live case status.
            </p>
            <button className="btn" onClick={() => navigate("/my-complaints")}>
              View My Cases →
            </button>
          </div>
        </div>

        {/* Info strip */}
        <div style={{
          marginTop: 24, padding: '12px 18px',
          background: 'rgba(56,189,248,0.04)',
          border: '1px solid rgba(56,189,248,0.1)',
          borderRadius: 12,
          display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap',
        }}>
          <span style={{ fontSize: 13, color: '#64748b' }}>
            🛡️ Rakshak AI uses hybrid ML (TF-IDF + Logistic Regression) for real-time threat classification.
            All submissions are encrypted and handled under defence-grade security protocols.
          </span>
        </div>
      </div>
    </div>
  );
}

export default Dashboard;
