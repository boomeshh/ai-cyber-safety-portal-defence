import { useEffect, useState } from "react";
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement,
} from "chart.js";
import { Pie, Bar, Line } from "react-chartjs-2";
import "./App.css";

ChartJS.register(
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  BarElement
);

function getRiskClass(level) {
  switch (level) {
    case "Critical":
      return "risk critical";
    case "High":
      return "risk high";
    case "Medium":
      return "risk medium";
    default:
      return "risk low";
  }
}

function App() {
  const [analytics, setAnalytics] = useState(null);
  const [certSummary, setCertSummary] = useState(null);
  const [feed, setFeed] = useState({
    live_alerts: [],
    escalated_cases: [],
    recent_cases: [],
  });
  const [lastUpdated, setLastUpdated] = useState("");

  const loadData = () => {
    fetch("http://127.0.0.1:8000/analytics")
      .then((res) => res.json())
      .then((data) => setAnalytics(data))
      .catch(() => console.log("analytics load failed"));

    fetch("http://127.0.0.1:8000/cert/summary")
      .then((res) => res.json())
      .then((data) => setCertSummary(data))
      .catch(() => console.log("summary load failed"));

    fetch("http://127.0.0.1:8000/cert/full-feed")
      .then((res) => res.json())
      .then((data) => setFeed(data))
      .catch(() => console.log("feed load failed"));

    setLastUpdated(new Date().toLocaleTimeString());
  };

  useEffect(() => {
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, []);

  if (!analytics || !certSummary) {
    return (
      <div className="loading-screen">
        <h2>Loading CERT Command Center...</h2>
      </div>
    );
  }

  const threatChartData = {
    labels: Object.keys(analytics.threat_distribution || {}),
    datasets: [
      {
        data: Object.values(analytics.threat_distribution || {}),
        backgroundColor: ["#22c55e", "#f59e0b", "#ef4444", "#3b82f6", "#8b5cf6"],
        borderColor: "#081120",
        borderWidth: 3,
      },
    ],
  };

  const riskBarData = {
    labels: Object.keys(analytics.risk_distribution || {}),
    datasets: [
      {
        label: "Cases by Risk Level",
        data: Object.values(analytics.risk_distribution || {}),
        backgroundColor: ["#16a34a", "#d97706", "#ea580c", "#dc2626"],
      },
    ],
  };

  const dailyTrendData = {
    labels: Object.keys(analytics.daily_trend || {}),
    datasets: [
      {
        label: "Daily Complaints Trend",
        data: Object.values(analytics.daily_trend || {}),
        borderColor: "#38bdf8",
        backgroundColor: "rgba(56, 189, 248, 0.2)",
        tension: 0.35,
        fill: true,
      },
    ],
  };

  return (
    <div className="cert-page">
      <div className="cert-shell">
        <div className="hero">
          <div>
            <div className="kicker">RAKSHAK AI</div>
            <h1>CERT Command Center</h1>
            <p>
              Centralized monitoring interface for critical cyber complaints,
              escalations, and threat distribution across the defence safety system.
            </p>
          </div>

          <div className="hero-right">
            <div className="live-pill">
              <span className="pulse-dot"></span>
              Auto Refresh: 5s
            </div>
            <div className="updated-time">Last Updated: {lastUpdated}</div>
          </div>
        </div>

        {certSummary.critical_alerts > 0 ? (
          <div className="alert-banner">
            🚨 ACTIVE CRITICAL ALERTS: {certSummary.critical_alerts} high-priority case(s) require immediate CERT review.
          </div>
        ) : (
          <div className="alert-banner safe">
            ✅ No critical alerts at the moment. System currently stable.
          </div>
        )}

        <div className="summary-grid">
          <div className="summary-card">
            <div className="summary-label">Total Cases</div>
            <div className="summary-value">{certSummary.total_cases}</div>
          </div>

          <div className="summary-card critical-card">
            <div className="summary-label">Critical Alerts</div>
            <div className="summary-value">{certSummary.critical_alerts}</div>
          </div>

          <div className="summary-card">
            <div className="summary-label">Open Cases</div>
            <div className="summary-value">{certSummary.open_cases}</div>
          </div>

          <div className="summary-card">
            <div className="summary-label">Escalated Cases</div>
            <div className="summary-value">{certSummary.escalated_cases}</div>
          </div>
        </div>

        <div className="chart-grid">
          <div className="panel">
            <div className="panel-header">
              <h2>Threat Distribution</h2>
              <span className="panel-tag">Pie</span>
            </div>
            <div className="chart-wrap">
              <Pie data={threatChartData} />
            </div>
          </div>

          <div className="panel">
            <div className="panel-header">
              <h2>Risk Distribution</h2>
              <span className="panel-tag">Bar</span>
            </div>
            <div className="bar-wrap">
              <Bar data={riskBarData} />
            </div>
          </div>
        </div>

        <div className="panel trend-panel">
          <div className="panel-header">
            <h2>Daily Complaint Trend</h2>
            <span className="panel-tag">Line</span>
          </div>
          <div className="line-wrap">
            <Line data={dailyTrendData} />
          </div>
        </div>

        <div className="bottom-grid">
          <div className="panel">
            <div className="panel-header">
              <h2>Live Critical Alerts</h2>
              <span className="panel-tag red-tag">{feed.live_alerts.length}</span>
            </div>

            {feed.live_alerts.length === 0 ? (
              <div className="empty-state">No critical alerts right now.</div>
            ) : (
              <div className="list-wrap">
                {feed.live_alerts.map((item) => (
                  <div className="incident-card critical-border" key={item.id}>
                    <div className="incident-top">
                      <strong>{item.id}</strong>
                      <span className={getRiskClass(item.risk_level)}>{item.risk_level}</span>
                    </div>
                    <p><strong>User:</strong> {item.user_name}</p>
                    <p><strong>Threat:</strong> {item.threat_type}</p>
                    <p><strong>Score:</strong> {item.risk_score}</p>
                    <p><strong>Status:</strong> {item.status}</p>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="panel">
            <div className="panel-header">
              <h2>Escalated Queue</h2>
              <span className="panel-tag amber-tag">{feed.escalated_cases.length}</span>
            </div>

            {feed.escalated_cases.length === 0 ? (
              <div className="empty-state">No escalated cases available.</div>
            ) : (
              <div className="list-wrap">
                {feed.escalated_cases.map((item) => (
                  <div className="incident-card" key={item.id}>
                    <div className="incident-top">
                      <strong>{item.id}</strong>
                      <span className={getRiskClass(item.risk_level)}>{item.risk_level}</span>
                    </div>
                    <p><strong>User:</strong> {item.user_name}</p>
                    <p><strong>Threat:</strong> {item.threat_type}</p>
                    <p><strong>Date:</strong> {item.created_at}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        <div className="panel recent-panel">
          <div className="panel-header">
            <h2>Recent Incident Feed</h2>
            <span className="panel-tag">Live Feed</span>
          </div>

          {feed.recent_cases.length === 0 ? (
            <div className="empty-state">No recent incidents available.</div>
          ) : (
            <div className="table-wrap">
              <table className="mini-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>User</th>
                    <th>Threat</th>
                    <th>Risk</th>
                  </tr>
                </thead>
                <tbody>
                  {feed.recent_cases.map((item) => (
                    <tr key={item.id}>
                      <td>{item.id}</td>
                      <td>{item.user_name}</td>
                      <td>{item.threat_type}</td>
                      <td>
                        <span className={getRiskClass(item.risk_level)}>
                          {item.risk_level}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;