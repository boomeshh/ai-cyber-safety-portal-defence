import { useEffect, useMemo, useState } from 'react';
import './App.css';
import { getAuthHeaders, getStoredUser, logoutUser } from './utils/auth';

const API = 'http://127.0.0.1:8000';

function getRiskClass(level) {
  switch (level) {
    case 'Critical': return 'risk critical';
    case 'High': return 'risk high';
    case 'Medium': return 'risk medium';
    default: return 'risk low';
  }
}

function LoginGate({ onLogin }) {
  const [email, setEmail] = useState('cert@rakshak.ai');
  const [password, setPassword] = useState('cert123');
  const [error, setError] = useState('');
  const handleLogin = async (e) => {
    e.preventDefault(); setError('');
    try {
      const res = await fetch(`${API}/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
      const data = await res.json();
      if (!data.success) throw new Error(data.message || 'Login failed');
      if (!['cert', 'admin'].includes(data.user.role)) throw new Error('This account cannot access CERT dashboard');
      localStorage.setItem('token', data.token); localStorage.setItem('user', JSON.stringify(data.user)); onLogin(data.user);
    } catch (err) { setError(err.message); }
  };
  return <div className="loading-screen"><div className="panel" style={{ maxWidth: 420, width: '100%' }}><div className="panel-header"><h2>CERT Secure Login</h2></div><p style={{ color: '#cbd5e1', marginBottom: 16 }}>Use a <strong>cert</strong> or <strong>admin</strong> role account.</p><form onSubmit={handleLogin} style={{ display: 'grid', gap: 12 }}><input style={inputStyle} value={email} onChange={(e) => setEmail(e.target.value)} /><input style={inputStyle} type="password" value={password} onChange={(e) => setPassword(e.target.value)} />{error ? <div style={{ color: '#fca5a5' }}>{error}</div> : null}<button style={buttonStyle}>Enter CERT Command Center</button></form></div></div>;
}

export default function App() {
  const [user, setUser] = useState(getStoredUser());
  const [intel, setIntel] = useState(null);
  const [error, setError] = useState('');
  const [lastUpdated, setLastUpdated] = useState('');

  const loadData = async () => {
    try {
      const res = await fetch(`${API}/cert/intel`, { headers: getAuthHeaders() });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'CERT data load failed');
      setIntel(data); setLastUpdated(new Date().toLocaleTimeString()); setError('');
    } catch (err) {
      setError(err.message);
      if (err.message.toLowerCase().includes('session') || err.message.toLowerCase().includes('missing')) { logoutUser(); setUser(null); }
    }
  };

  useEffect(() => {
    if (!user || !['cert', 'admin'].includes(user.role)) return;
    loadData(); const interval = setInterval(loadData, 5000); return () => clearInterval(interval);
  }, [user]);

  const summary = intel?.summary;
  const analytics = intel?.analytics;
  const feed = intel?.feed;
  const graph = intel?.campaign_graph;
  const channelRows = useMemo(() => Object.entries(analytics?.channel_distribution || {}), [analytics]);
  const riskRows = useMemo(() => Object.entries(analytics?.risk_distribution || {}), [analytics]);

  if (!user || !['cert', 'admin'].includes(user.role)) return <LoginGate onLogin={setUser} />;
  if (!intel && !error) return <div className="loading-screen"><h2>Loading CERT Command Center...</h2></div>;
  if (error && !intel) return <div className="loading-screen"><div className="panel"><h2>CERT dashboard unavailable</h2><p>{error}</p><button style={buttonStyle} onClick={loadData}>Retry</button></div></div>;

  return (
    <div className="cert-page">
      <div className="cert-shell">
        <div className="hero">
          <div>
            <div className="kicker">RAKSHAK AI · PHASE 3</div>
            <h1>CERT Command Center</h1>
            <p>Protected operational dashboard for live alerts, escalations, linked campaigns, evidence-ready review, and OPSEC-sensitive incidents.</p>
          </div>
          <div className="hero-right">
            <div className="live-pill"><span className="pulse-dot"></span>Auto Refresh: 5s</div>
            <div className="updated-time">{user.full_name} · {user.role}</div>
            <div className="updated-time">Last Updated: {lastUpdated}</div>
            <div style={{ display: 'flex', gap: 10 }}>
              <a href={`${API}/download/excel`} target="_blank" rel="noreferrer" style={{ ...buttonStyle, textDecoration: 'none', display: 'inline-block' }}>Export Excel</a>
              <button style={buttonStyle} onClick={() => { logoutUser(); setUser(null); }}>Logout</button>
            </div>
          </div>
        </div>

        {summary?.critical_alerts > 0 ? <div className="alert-banner">🚨 ACTIVE CRITICAL ALERTS: {summary.critical_alerts} case(s) require immediate CERT review.</div> : <div className="alert-banner safe">✅ No critical alerts at the moment. System currently stable.</div>}

        <div className="summary-grid">
          <SummaryCard label="Total Cases" value={summary?.total_cases} />
          <SummaryCard label="Critical Alerts" value={summary?.critical_alerts} critical />
          <SummaryCard label="Escalated" value={summary?.escalated_cases} />
          <SummaryCard label="Linked Campaigns" value={summary?.linked_campaigns} />
          <SummaryCard label="OPSEC Priority" value={summary?.opsec_priority} />
          <SummaryCard label="Top Score" value={summary?.highest_risk_score} />
        </div>

        <div className="chart-grid">
          <div className="panel">
            <div className="panel-header"><h2>Risk Distribution</h2><span className="panel-tag">Priority</span></div>
            <MetricBars rows={riskRows} />
          </div>
          <div className="panel">
            <div className="panel-header"><h2>Attack Channel Distribution</h2><span className="panel-tag">Ops</span></div>
            <MetricBars rows={channelRows} />
          </div>
        </div>

        <div className="chart-grid">
          <div className="panel">
            <div className="panel-header"><h2>Campaign Link Graph</h2><span className="panel-tag">Phase 3</span></div>
            {graph?.nodes?.length ? <CampaignGraph graph={graph} /> : <div className="empty-state">No linked campaign graph available yet.</div>}
          </div>
          <div className="panel">
            <div className="panel-header"><h2>OPSEC / Espionage Priority</h2><span className="panel-tag red-tag">Sensitive</span></div>
            <div className="list-wrap">
              {(feed?.opsec_cases || []).length === 0 ? <div className="empty-state">No OPSEC priority cases yet.</div> : feed.opsec_cases.map((item) => <IncidentCard key={item.id} item={item} showReason />)}
            </div>
          </div>
        </div>

        <div className="bottom-grid">
          <div className="panel">
            <div className="panel-header"><h2>Live Critical Alerts</h2><span className="panel-tag red-tag">{feed?.live_alerts?.length || 0}</span></div>
            <div className="list-wrap">{(feed?.live_alerts || []).map((item) => <IncidentCard key={item.id} item={item} />)}</div>
          </div>
          <div className="panel">
            <div className="panel-header"><h2>Repeated Campaign Indicators</h2><span className="panel-tag amber-tag">Intel</span></div>
            <div className="list-wrap">{(feed?.repeated_cases || []).length === 0 ? <div className="empty-state">No linked campaign patterns yet.</div> : feed.repeated_cases.map((item) => <IncidentCard key={item.id} item={item} campaign />)}</div>
          </div>
        </div>

        <div className="panel recent-panel">
          <div className="panel-header"><h2>Recent Incident Feed</h2><span className="panel-tag">Live Feed</span></div>
          <div className="table-wrap"><table className="mini-table"><thead><tr><th>ID</th><th>User</th><th>Threat</th><th>Risk</th><th>Status</th><th>Channel</th></tr></thead><tbody>{(feed?.recent_cases || []).map((item) => <tr key={item.id}><td>{item.id}</td><td>{item.user_name}</td><td>{item.threat_type}</td><td><span className={getRiskClass(item.risk_level)}>{item.risk_level}</span></td><td>{item.status}</td><td>{item.attack_channel || 'Unknown'}</td></tr>)}</tbody></table></div>
        </div>
      </div>
    </div>
  );
}

function SummaryCard({ label, value, critical }) {
  return <div className={`summary-card ${critical ? 'critical-card' : ''}`}><div className="summary-label">{label}</div><div className="summary-value">{value ?? 0}</div></div>;
}

function IncidentCard({ item, campaign, showReason }) {
  return (
    <div className="incident-card critical-border">
      <div className="incident-top"><strong>{item.id}</strong><span className={getRiskClass(item.risk_level)}>{item.risk_level}</span></div>
      <p><strong>User:</strong> {item.user_name}</p>
      <p><strong>Threat:</strong> {item.threat_type}</p>
      <p><strong>Score:</strong> {item.risk_score}</p>
      <p><strong>Status:</strong> {item.status}</p>
      <p><strong>Channel:</strong> {item.attack_channel || 'Unknown'}</p>
      {campaign ? <p className="campaign-chip">⚠ Linked with {item.linked_case_count} earlier case(s)</p> : null}
      {showReason ? <p><strong>AI Note:</strong> {(item.ai_reason || '').split('\n\n')[1]?.replace('Risk Explanation:\n', '') || 'Sensitive priority pattern detected.'}</p> : null}
    </div>
  );
}

function MetricBars({ rows }) {
  const max = Math.max(...rows.map(([, value]) => Number(value || 0)), 1);
  return <div className="bars">{rows.length === 0 ? <div className="empty-state">No analytics yet.</div> : rows.map(([label, value]) => <div className="bar-row" key={label}><div className="bar-label">{label}</div><div className="bar-track"><div className="bar-fill" style={{ width: `${(Number(value || 0) / max) * 100}%` }}></div></div><div className="bar-value">{value}</div></div>)}</div>;
}

function CampaignGraph({ graph }) {
  return <div className="graph-grid">{graph.nodes.map((node) => <div key={node.id} className={`graph-node ${node.kind} ${node.severity}`}><div className="graph-kind">{node.kind}</div><div className="graph-label">{node.label}</div></div>)}<div className="graph-edge-list"><strong>Connections</strong>{graph.edges.map((edge, index) => <div key={`${edge.source}-${edge.target}-${index}`} className="edge-item">{short(edge.source)} → {short(edge.target)} <span>{edge.label}</span></div>)}</div></div>;
}

function short(value) { return value.length > 20 ? `${value.slice(0, 20)}...` : value; }

const inputStyle = { background: '#0f172a', color: 'white', border: '1px solid #334155', borderRadius: 10, padding: '10px 12px' };
const buttonStyle = { background: 'linear-gradient(135deg, #38bdf8, #22c55e)', color: '#081120', border: 'none', borderRadius: 10, padding: '10px 14px', cursor: 'pointer', fontWeight: 700 };
