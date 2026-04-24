import { useEffect, useMemo, useRef, useState } from 'react';
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  BarElement,
  LineElement,
  PointElement,
  Title,
  Tooltip,
  Legend,
  Filler,
} from 'chart.js';
import { Line } from 'react-chartjs-2';
import './App.css';
import { getAuthHeaders, getStoredUser, logoutUser } from './utils/auth';
import Heatmap from './components/Heatmap';

ChartJS.register(
  CategoryScale, LinearScale, BarElement,
  LineElement, PointElement, Title, Tooltip, Legend, Filler
);

const API = 'http://127.0.0.1:8000';

function getRiskClass(level) {
  switch (level) {
    case 'Critical': return 'risk critical';
    case 'High':     return 'risk high';
    case 'Medium':   return 'risk medium';
    default:         return 'risk low';
  }
}

// ─── Login Gate ────────────────────────────────────────────────────────────
function LoginGate({ onLogin }) {
  const [email, setEmail] = useState('cert@rakshak.ai');
  const [password, setPassword] = useState('cert123');
  const [error, setError] = useState('');

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    try {
      const res = await fetch(`${API}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });
      const data = await res.json();
      if (!data.success) throw new Error(data.message || 'Login failed');
      if (!['cert', 'admin'].includes(data.user.role))
        throw new Error('This account cannot access CERT dashboard');
      localStorage.setItem('token', data.token);
      localStorage.setItem('user', JSON.stringify(data.user));
      onLogin(data.user);
    } catch (err) {
      setError(err.message || 'Login failed');
    }
  };

  return (
    <div className="loading-screen">
      <div className="panel" style={{ maxWidth: 420, width: '100%' }}>
        <div className="panel-header"><h2>CERT Secure Login</h2></div>
        <p style={{ color: '#cbd5e1', marginBottom: 16 }}>
          Use a <strong>cert</strong> or <strong>admin</strong> role account.
        </p>
        <form onSubmit={handleLogin} style={{ display: 'grid', gap: 12 }}>
          <input style={inputStyle} value={email} onChange={(e) => setEmail(e.target.value)} />
          <input style={inputStyle} type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
          {error ? <div style={{ color: '#fca5a5' }}>{error}</div> : null}
          <button type="submit" style={buttonStyle}>Enter CERT Command Center</button>
        </form>
      </div>
    </div>
  );
}

// ─── Main App ───────────────────────────────────────────────────────────────
export default function App() {
  const [user, setUser] = useState(getStoredUser());
  const [intel, setIntel] = useState(null);
  const [error, setError] = useState('');
  const [lastUpdated, setLastUpdated] = useState('');
  const [exporting, setExporting] = useState(false);
  const [training, setTraining] = useState(false);
  const [trainResult, setTrainResult] = useState(null);

  const loadData = async () => {
    try {
      const res = await fetch(`${API}/cert/intel`, { headers: getAuthHeaders() });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'CERT data load failed');
      setIntel(data);
      setLastUpdated(new Date().toLocaleTimeString());
      setError('');
    } catch (err) {
      const message = err.message || 'CERT data load failed';
      setError(message);
      if (message.toLowerCase().includes('session') || message.toLowerCase().includes('missing')) {
        logoutUser(); setUser(null);
      }
    }
  };

  const handleExportExcel = async () => {
    try {
      setExporting(true);
      const res = await fetch(`${API}/download/excel`, { headers: getAuthHeaders() });
      if (!res.ok) {
        const errData = await res.json().catch(() => ({}));
        throw new Error(errData.detail || `Download failed (${res.status})`);
      }
      const blob = await res.blob();
      const disposition = res.headers.get('content-disposition') || '';
      const match = disposition.match(/filename\*=UTF-8''([^;]+)|filename="?([^\";]+)"?/i);
      const fileName = decodeURIComponent(match?.[1] || match?.[2] || 'complaints_export.xlsx');
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = fileName;
      document.body.appendChild(a); a.click(); a.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert(err.message);
    } finally {
      setExporting(false);
    }
  };

  const handleTrainModel = async () => {
    try {
      setTraining(true);
      setTrainResult(null);
      const res = await fetch(`${API}/ai/train`, { method: 'POST', headers: getAuthHeaders() });
      const data = await res.json();
      setTrainResult(data);
      await loadData(); // refresh model_info
    } catch (err) {
      setTrainResult({ success: false, error: err.message });
    } finally {
      setTraining(false);
    }
  };

  useEffect(() => {
    if (!user || !['cert', 'admin'].includes(user.role)) return;
    loadData();
    const interval = setInterval(loadData, 5000);
    return () => clearInterval(interval);
  }, [user]);

  const summary = intel?.summary;
  const analytics = intel?.analytics;
  const feed = intel?.feed;
  const graph = intel?.campaign_graph;
  const heatmaps = intel?.heatmaps;
  const modelInfo = intel?.model_info;
  const campaignClusters = intel?.campaign_clusters || [];

  const channelRows = useMemo(() => Object.entries(analytics?.channel_distribution || {}), [analytics]);
  const riskRows = useMemo(() => Object.entries(analytics?.risk_distribution || {}), [analytics]);

  // Daily trend chart data
  const trendData = useMemo(() => {
    const trend = analytics?.daily_trend || {};
    const sorted = Object.entries(trend).sort(([a], [b]) => a.localeCompare(b)).slice(-14);
    return {
      labels: sorted.map(([d]) => d),
      datasets: [{
        label: 'Incidents',
        data: sorted.map(([, v]) => v),
        fill: true,
        borderColor: '#38bdf8',
        backgroundColor: 'rgba(56,189,248,0.12)',
        tension: 0.4,
        pointBackgroundColor: '#38bdf8',
        pointRadius: 4,
      }],
    };
  }, [analytics]);

  const trendOptions = {
    responsive: true,
    plugins: { legend: { display: false }, tooltip: { mode: 'index' } },
    scales: {
      x: { ticks: { color: '#64748b' }, grid: { color: '#1e293b' } },
      y: { ticks: { color: '#64748b' }, grid: { color: '#1e293b' }, beginAtZero: true },
    },
  };

  if (!user || !['cert', 'admin'].includes(user.role)) return <LoginGate onLogin={setUser} />;

  if (!intel && !error) {
    return <div className="loading-screen"><h2>Loading CERT Command Center...</h2></div>;
  }

  if (error && !intel) {
    return (
      <div className="loading-screen">
        <div className="panel">
          <h2>CERT dashboard unavailable</h2>
          <p>{error}</p>
          <button style={buttonStyle} onClick={loadData}>Retry</button>
        </div>
      </div>
    );
  }

  return (
    <div className="cert-page">
      <div className="cert-shell">

        {/* ── Header ── */}
        <div className="hero">
          <div>
            <div className="kicker">RAKSHAK AI · HYBRID ML ENGINE</div>
            <h1>CERT Command Center</h1>
            <p>
              Operational intelligence dashboard — live alerts, ML threat analysis,
              heatmap intelligence, campaign clusters, and OPSEC-sensitive incident review.
            </p>
            <div className="engine-badge">
              <span className="engine-dot" />
              Hybrid AI Engine Active &nbsp;·&nbsp; TF-IDF + LogisticRegression
              {modelInfo?.fallback_active && (
                <span className="engine-fallback"> · Rule-Based Fallback</span>
              )}
            </div>
          </div>
          <div className="hero-right">
            <div className="live-pill">
              <span className="pulse-dot" />
              Auto Refresh: 5s
            </div>
            <div className="updated-time">{user.full_name} · {user.role}</div>
            <div className="updated-time">Last Updated: {lastUpdated}</div>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              <button style={buttonStyle} onClick={handleExportExcel} disabled={exporting}>
                {exporting ? 'Exporting...' : 'Export Excel'}
              </button>
              <button style={{ ...buttonStyle, background: 'linear-gradient(135deg,#f59e0b,#f97316)' }}
                onClick={() => { logoutUser(); setUser(null); }}>
                Logout
              </button>
            </div>
          </div>
        </div>

        {/* ── Critical Alert Banner ── */}
        {summary?.critical_alerts > 0 ? (
          <div className="alert-banner">
            🚨 ACTIVE CRITICAL ALERTS: {summary.critical_alerts} case(s) require immediate CERT review.
          </div>
        ) : (
          <div className="alert-banner safe">
            ✅ No critical alerts at the moment. System currently stable.
          </div>
        )}

        {/* ── Summary Grid ── */}
        <div className="summary-grid">
          <SummaryCard label="Total Incidents" value={summary?.total_cases} />
          <SummaryCard label="Critical Alerts" value={summary?.critical_alerts} critical />
          <SummaryCard label="Escalated Cases" value={summary?.escalated_cases} />
          <SummaryCard label="Campaign Clusters" value={campaignClusters.length} />
          <SummaryCard label="ML Model" value={modelInfo?.model_exists ? 'Active' : 'Fallback'} text />
          <SummaryCard label="Avg AI Confidence" value={summary?.avg_ai_confidence != null ? `${summary.avg_ai_confidence}%` : 'N/A'} text />
        </div>

        {/* ── Model Intelligence Panel ── */}
        <div className="panel" style={{ marginBottom: 24 }}>
          <div className="panel-header">
            <h2>Model Intelligence</h2>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              <span className={`panel-tag ${modelInfo?.model_exists ? '' : 'red-tag'}`}>
                {modelInfo?.model_exists ? '✓ LogisticRegression Active' : '⚠ Fallback Mode'}
              </span>
              {user.role === 'admin' && (
                <button style={{ ...buttonStyle, padding: '7px 14px', fontSize: '0.85rem' }}
                  onClick={handleTrainModel} disabled={training}>
                  {training ? 'Training...' : 'Retrain Model'}
                </button>
              )}
            </div>
          </div>
          <div className="model-grid">
            <ModelStat label="Algorithm" value={modelInfo?.algorithm || 'LogisticRegression'} />
            <ModelStat
              label="Trained At"
              value={modelInfo?.trained_at ? new Date(modelInfo.trained_at).toLocaleString() : 'Not trained yet'}
            />
            <ModelStat label="Training Samples" value={modelInfo?.sample_count ?? '—'} />
            <ModelStat label="Feature Count" value={modelInfo?.feature_count ?? '—'} />
            <ModelStat
              label="Training Accuracy"
              value={modelInfo?.training_accuracy != null
                ? `${(modelInfo.training_accuracy * 100).toFixed(1)}%`
                : '—'}
            />
            <ModelStat
              label="Avg AI Confidence"
              value={summary?.avg_ai_confidence != null ? `${summary.avg_ai_confidence}%` : '—'}
            />
          </div>

          {modelInfo?.warning && (
            <div style={{ color: '#fde68a', marginTop: 12, fontSize: '0.88rem' }}>
              ⚠ {modelInfo.warning}
            </div>
          )}

          {modelInfo?.classes?.length > 0 && (
            <div style={{ marginTop: 14 }}>
              <div style={{ color: '#64748b', fontSize: '0.78rem', marginBottom: 6, fontWeight: 700, letterSpacing: '0.5px' }}>
                THREAT CLASSES
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {modelInfo.classes.map((cls) => (
                  <span key={cls} className="panel-tag" style={{ fontSize: '0.78rem' }}>{cls}</span>
                ))}
              </div>
            </div>
          )}

          {trainResult && (
            <div style={{ marginTop: 14, padding: '12px 16px', background: '#0b1220', borderRadius: 12, border: '1px solid #1e293b' }}>
              {trainResult.success
                ? <span style={{ color: '#22c55e' }}>
                    ✓ Model retrained — {trainResult.sample_count} samples
                    {trainResult.training_accuracy != null
                      ? `, accuracy: ${(trainResult.training_accuracy * 100).toFixed(1)}%`
                      : ''}
                  </span>
                : <span style={{ color: '#fca5a5' }}>✗ Training failed: {trainResult.error || 'Unknown error'}</span>
              }
              {trainResult.warning && (
                <div style={{ color: '#fde68a', marginTop: 6, fontSize: '0.85rem' }}>⚠ {trainResult.warning}</div>
              )}
            </div>
          )}
        </div>

        {/* ── Heatmap Intelligence Panel ── */}
        <div className="panel heatmap-panel" style={{ marginBottom: 24 }}>
          <div className="panel-header">
            <h2>Heatmap Intelligence</h2>
            <span className="panel-tag amber-tag">Threat Patterns</span>
          </div>

          {/* Row 1: Hour vs Day — full width, scrollable internally */}
          <div className="heatmap-row-full">
            <Heatmap
              title={heatmaps?.hourly_risk_heatmap?.title || 'Hour vs Day Threat Heatmap'}
              x_labels={heatmaps?.hourly_risk_heatmap?.x_labels || []}
              y_labels={heatmaps?.hourly_risk_heatmap?.y_labels || []}
              values={heatmaps?.hourly_risk_heatmap?.values || []}
            />
          </div>

          {/* Row 2: Channel vs Risk + Category vs Channel side by side */}
          <div className="heatmap-row-pair">
            <div className="heatmap-pair-cell">
              <Heatmap
                title={heatmaps?.channel_risk_heatmap?.title || 'Channel vs Risk Heatmap'}
                x_labels={heatmaps?.channel_risk_heatmap?.x_labels || []}
                y_labels={heatmaps?.channel_risk_heatmap?.y_labels || []}
                values={heatmaps?.channel_risk_heatmap?.values || []}
              />
            </div>
            <div className="heatmap-pair-cell">
              <Heatmap
                title={heatmaps?.category_channel_heatmap?.title || 'Category vs Channel Heatmap'}
                x_labels={heatmaps?.category_channel_heatmap?.x_labels || []}
                y_labels={heatmaps?.category_channel_heatmap?.y_labels || []}
                values={heatmaps?.category_channel_heatmap?.values || []}
              />
            </div>
          </div>
        </div>

        {/* ── Trend + Distributions ── */}
        <div className="chart-grid" style={{ marginBottom: 24 }}>
          <div className="panel">
            <div className="panel-header">
              <h2>Daily Incident Trend</h2>
              <span className="panel-tag">14 Days</span>
            </div>
            {trendData.labels.length > 0
              ? <Line data={trendData} options={trendOptions} />
              : <div className="empty-state">No trend data yet.</div>
            }
          </div>
          <div className="panel">
            <div className="panel-header">
              <h2>Risk Distribution</h2>
              <span className="panel-tag">Priority</span>
            </div>
            <MetricBars rows={riskRows} />
          </div>
        </div>

        <div className="chart-grid" style={{ marginBottom: 24 }}>
          <div className="panel">
            <div className="panel-header">
              <h2>Attack Channel Distribution</h2>
              <span className="panel-tag">Ops</span>
            </div>
            <MetricBars rows={channelRows} />
          </div>
          <div className="panel">
            <div className="panel-header">
              <h2>Campaign Link Graph</h2>
              <span className="panel-tag">Phase 3</span>
            </div>
            {graph?.nodes?.length
              ? <CampaignGraph graph={graph} />
              : <div className="empty-state">No linked campaign graph available yet.</div>
            }
          </div>
        </div>

        {/* ── Campaign Clusters ── */}
        {campaignClusters.length > 0 && (
          <div className="panel" style={{ marginBottom: 24 }}>
            <div className="panel-header">
              <h2>Campaign Clusters</h2>
              <span className="panel-tag amber-tag">{campaignClusters.length} cluster{campaignClusters.length !== 1 ? 's' : ''}</span>
            </div>
            <div className="cluster-grid">
              {campaignClusters.map((c, i) => (
                <div key={i} className={`cluster-card ${c.dominant_risk_level === 'Critical' ? 'cluster-critical' : ''}`}>
                  <div className="cluster-sig" title={c.signature}>{c.signature}</div>
                  <div className="cluster-row"><span>Cases</span><strong>{c.count}</strong></div>
                  <div className="cluster-row"><span>Category</span><strong>{c.dominant_category}</strong></div>
                  <div className="cluster-row"><span>Channel</span><strong>{c.dominant_channel}</strong></div>
                  <div className="cluster-row">
                    <span>Risk Level</span>
                    <strong className={`cluster-risk-${(c.dominant_risk_level || 'low').toLowerCase()}`}>
                      {c.dominant_risk_level || '—'}
                    </strong>
                  </div>
                  <div className="cluster-row"><span>Avg Score</span><strong>{c.avg_risk_score}</strong></div>
                  <div className="cluster-row">
                    <span>Avg Confidence</span>
                    <strong>{c.avg_confidence != null ? `${c.avg_confidence}%` : '—'}</strong>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Live Alerts + OPSEC ── */}
        <div className="bottom-grid" style={{ marginBottom: 24 }}>
          <div className="panel">
            <div className="panel-header">
              <h2>Live Critical Alerts</h2>
              <span className="panel-tag red-tag">{feed?.live_alerts?.length || 0}</span>
            </div>
            <div className="list-wrap">
              {(feed?.live_alerts || []).length === 0
                ? <div className="empty-state">No critical alerts.</div>
                : feed.live_alerts.map((item) => <IncidentCard key={item.id} item={item} />)
              }
            </div>
          </div>
          <div className="panel">
            <div className="panel-header">
              <h2>OPSEC / Espionage Priority</h2>
              <span className="panel-tag red-tag">Sensitive</span>
            </div>
            <div className="list-wrap">
              {(feed?.opsec_cases || []).length === 0
                ? <div className="empty-state">No OPSEC priority cases yet.</div>
                : feed.opsec_cases.map((item) => <IncidentCard key={item.id} item={item} showReason />)
              }
            </div>
          </div>
        </div>

        {/* ── Repeated Campaigns ── */}
        <div className="bottom-grid" style={{ marginBottom: 24 }}>
          <div className="panel">
            <div className="panel-header">
              <h2>Repeated Campaign Indicators</h2>
              <span className="panel-tag amber-tag">Intel</span>
            </div>
            <div className="list-wrap">
              {(feed?.repeated_cases || []).length === 0
                ? <div className="empty-state">No linked campaign patterns yet.</div>
                : feed.repeated_cases.map((item) => <IncidentCard key={item.id} item={item} campaign />)
              }
            </div>
          </div>
          <div className="panel">
            <div className="panel-header">
              <h2>Escalated Cases</h2>
              <span className="panel-tag amber-tag">{feed?.escalated_cases?.length || 0}</span>
            </div>
            <div className="list-wrap">
              {(feed?.escalated_cases || []).length === 0
                ? <div className="empty-state">No escalated cases.</div>
                : feed.escalated_cases.map((item) => <IncidentCard key={item.id} item={item} />)
              }
            </div>
          </div>
        </div>

        {/* ── Recent Incident Feed ── */}
        <div className="panel recent-panel">
          <div className="panel-header">
            <h2>Recent Incident Feed</h2>
            <span className="panel-tag">Live Feed</span>
          </div>
          <div className="table-wrap">
            <table className="mini-table">
              <thead>
                <tr>
                  <th>ID</th><th>User</th><th>Threat</th><th>ML Type</th>
                  <th>Risk</th><th>Confidence</th><th>Status</th><th>Channel</th>
                </tr>
              </thead>
              <tbody>
                {(feed?.recent_cases || []).map((item) => (
                  <tr key={item.id}>
                    <td>{item.id}</td>
                    <td>{item.user_name}</td>
                    <td>{item.threat_type}</td>
                    <td>{item.ml_predicted_type || item.ml_prediction || '—'}</td>
                    <td><span className={getRiskClass(item.risk_level)}>{item.risk_level}</span></td>
                    <td>{item.ai_confidence != null ? `${item.ai_confidence}%` : '—'}</td>
                    <td>{item.status}</td>
                    <td>{item.attack_channel || 'Unknown'}</td>
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

// ─── Sub-components ─────────────────────────────────────────────────────────

function SummaryCard({ label, value, critical, text }) {
  return (
    <div className={`summary-card ${critical ? 'critical-card' : ''}`}>
      <div className="summary-label">{label}</div>
      <div className={`summary-value ${text ? 'summary-text' : ''}`}>{value ?? 0}</div>
    </div>
  );
}

function ModelStat({ label, value }) {
  return (
    <div className="model-stat">
      <div className="model-stat-label">{label}</div>
      <div className="model-stat-value">{value ?? '—'}</div>
    </div>
  );
}

function IncidentCard({ item, campaign, showReason }) {
  return (
    <div className="incident-card critical-border">
      <div className="incident-top">
        <strong>{item.id}</strong>
        <span className={getRiskClass(item.risk_level)}>{item.risk_level}</span>
      </div>
      <p><strong>User:</strong> {item.user_name}</p>
      <p><strong>Threat:</strong> {item.threat_type}</p>
      <p><strong>Score:</strong> {item.risk_score} · Confidence: {item.ai_confidence != null ? `${item.ai_confidence}%` : '—'}</p>
      <p><strong>Status:</strong> {item.status}</p>
      <p><strong>Channel:</strong> {item.attack_channel || 'Unknown'}</p>
      {campaign && (
        <p className="campaign-chip">⚠ Linked with {item.linked_case_count} earlier case(s)</p>
      )}
      {showReason && (
        <p>
          <strong>AI Note:</strong>{' '}
          {(item.ai_reason || '').split('\n\n')[1]?.replace('Risk Explanation:\n', '') || 'Sensitive priority pattern detected.'}
        </p>
      )}
    </div>
  );
}

function MetricBars({ rows }) {
  const max = Math.max(...rows.map(([, v]) => Number(v || 0)), 1);
  return (
    <div className="bars">
      {rows.length === 0
        ? <div className="empty-state">No analytics yet.</div>
        : rows.map(([label, value]) => (
          <div className="bar-row" key={label}>
            <div className="bar-label">{label}</div>
            <div className="bar-track">
              <div className="bar-fill" style={{ width: `${(Number(value || 0) / max) * 100}%` }} />
            </div>
            <div className="bar-value">{value}</div>
          </div>
        ))
      }
    </div>
  );
}

function CampaignGraph({ graph }) {
  return (
    <div className="graph-grid">
      {graph.nodes.map((node) => (
        <div key={node.id} className={`graph-node ${node.kind} ${node.severity}`}>
          <div className="graph-kind">{node.kind}</div>
          <div className="graph-label">{node.label}</div>
        </div>
      ))}
      <div className="graph-edge-list">
        <strong>Connections</strong>
        {graph.edges.map((edge, i) => (
          <div key={i} className="edge-item">
            {short(edge.source)} → {short(edge.target)} <span>{edge.label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function short(v) {
  return v.length > 20 ? `${v.slice(0, 20)}...` : v;
}

const inputStyle = {
  background: '#0f172a', color: 'white',
  border: '1px solid #334155', borderRadius: 10, padding: '10px 12px',
};

const buttonStyle = {
  background: 'linear-gradient(135deg, #38bdf8, #22c55e)',
  color: '#081120', border: 'none', borderRadius: 10,
  padding: '10px 14px', cursor: 'pointer', fontWeight: 700,
};
