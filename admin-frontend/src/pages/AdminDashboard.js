import { useEffect, useMemo, useState } from 'react';
import { getAuthHeaders, getStoredUser, logoutUser } from '../utils/auth';

const API = process.env.REACT_APP_API_BASE_URL || 'https://ai-cyber-safety-portal-defence.onrender.com';
const statusOptions = ['Open', 'Under Review', 'Escalated', 'Action Initiated', 'Resolved', 'Archived'];

function getRiskBadgeClass(level) {
  switch (level) {
    case 'Critical': return 'risk-badge badge-critical';
    case 'High': return 'risk-badge badge-high';
    case 'Medium': return 'risk-badge badge-medium';
    default: return 'risk-badge badge-low';
  }
}

function LoginGate({ onLogin }) {
  const [email, setEmail] = useState('admin@rakshak.ai');
  const [password, setPassword] = useState('admin123');
  const [error, setError] = useState('');
  const handleLogin = async (e) => {
    e.preventDefault(); setError('');
    try {
      const res = await fetch(`${API}/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password }) });
      const data = await res.json();
      if (!data.success) throw new Error(data.message || 'Login failed');
      if (data.user.role !== 'admin') throw new Error('This account cannot access admin dashboard');
      localStorage.setItem('token', data.token); localStorage.setItem('user', JSON.stringify(data.user)); onLogin(data.user);
    } catch (err) { setError(err.message); }
  };
  return <div className="loading-screen"><div className="panel" style={{ maxWidth: 420, width: '100%' }}><div className="panel-header"><h2>Admin Secure Access</h2></div><p style={{ color: '#cbd5e1', marginBottom: 16 }}>Use an account with role <strong>admin</strong> to access triage, users, and audit logs.</p><form onSubmit={handleLogin} style={{ display: 'grid', gap: 12 }}><input style={inputStyle} value={email} onChange={(e) => setEmail(e.target.value)} /><input style={inputStyle} type="password" value={password} onChange={(e) => setPassword(e.target.value)} />{error ? <div style={{ color: '#fca5a5' }}>{error}</div> : null}<button style={buttonStyle}>Enter Admin Dashboard</button></form></div></div>;
}

export default function AdminDashboard() {
  const [user, setUser] = useState(getStoredUser());
  const [overview, setOverview] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [statusFilter, setStatusFilter] = useState('All');
  const [riskFilter, setRiskFilter] = useState('All');
  const [evidenceError, setEvidenceError] = useState('');

  const loadDashboardData = async () => {
    try {
      setLoading(true);
      const res = await fetch(`${API}/admin/overview`, { headers: getAuthHeaders() });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Failed to load dashboard');
      setOverview(data); setError('');
    } catch (err) {
      setError(err.message);
      if (err.message.toLowerCase().includes('session') || err.message.toLowerCase().includes('missing')) { logoutUser(); setUser(null); }
    } finally { setLoading(false); }
  };

  useEffect(() => { if (user?.role === 'admin') loadDashboardData(); else setLoading(false); }, [user]);

  const handleStatusChange = async (caseId, newStatus) => {
    try {
      const res = await fetch(`${API}/update-status/${caseId}?status=${encodeURIComponent(newStatus)}`, { method: 'PUT', headers: getAuthHeaders() });
      const data = await res.json();
      if (!res.ok || !data.success) throw new Error(data.detail || data.message || 'Status update failed');
      loadDashboardData();
    } catch (err) { alert(err.message); }
  };

  const openEvidence = async (complaintId) => {
    try {
      setEvidenceError('');
      const res = await fetch(`${API}/complaints/${complaintId}/evidence`, { headers: getAuthHeaders() });
      if (!res.ok) throw new Error(`Request failed: ${res.status}`);
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      window.open(url, '_blank');
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    } catch (err) {
      setEvidenceError('Failed to open evidence: ' + err.message);
    }
  };

  const filteredComplaints = useMemo(() => {
    const complaints = overview?.complaints || [];
    return complaints.filter((item) => (statusFilter === 'All' || item.status === statusFilter) && (riskFilter === 'All' || item.risk_level === riskFilter));
  }, [overview, statusFilter, riskFilter]);

  if (!user || user.role !== 'admin') return <LoginGate onLogin={setUser} />;
  if (loading) return <div className="loading-screen"><h2>Loading Admin Control Room...</h2></div>;
  if (error) return <div className="dashboard-shell" style={{ minHeight: '100vh', display: 'grid', placeItems: 'center' }}><div className="panel" style={{ maxWidth: 520 }}><h2>Admin dashboard unavailable</h2><p style={{ color: '#cbd5e1' }}>{error}</p><button style={buttonStyle} onClick={loadDashboardData}>Retry</button></div></div>;

  const analytics = overview?.analytics || {};
  const auditLogs = overview?.audit_logs || [];
  const users = overview?.users || [];
  const graph = overview?.campaign_graph;

  return (
    <div className="dashboard-shell">
      <div className="dashboard-topbar">
        <div><h1 style={{ marginBottom: 6 }}>Admin Triage Dashboard</h1><p style={{ color: '#94a3b8' }}>Role-based review, case operations, user registry, audit visibility, and campaign intelligence.</p></div>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}><div style={{ color: '#cbd5e1', fontSize: 14 }}>{user.full_name} · {user.role}</div><button style={buttonStyle} onClick={() => { logoutUser(); setUser(null); }}>Logout</button></div>
      </div>

      <div className="stats-grid">
        <StatCard label="Total Cases" value={analytics.total} />
        <StatCard label="Critical" value={analytics.critical} tone="critical" />
        <StatCard label="Open" value={analytics.open_cases} />
        <StatCard label="Escalated" value={analytics.escalated} />
        <StatCard label="Linked Indicators" value={analytics.linked_indicator_cases} />
        <StatCard label="Auto Escalated" value={analytics.auto_escalated_cases} />
      </div>

      <div className="panel" style={{ marginTop: 22 }}>
        <div className="panel-header"><h2>Complaint Queue</h2><div style={{ display: 'flex', gap: 10 }}><select value={riskFilter} onChange={(e) => setRiskFilter(e.target.value)} style={inputStyle}><option>All</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option></select><select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} style={inputStyle}><option>All</option>{statusOptions.map((s) => <option key={s}>{s}</option>)}</select></div></div>
        <div className="table-wrap"><table className="complaints-table"><thead><tr><th>ID</th><th>User</th><th>Threat</th><th>Risk</th><th>Channel</th><th>Linked</th><th>Evidence</th><th>Status</th><th>Date</th></tr></thead><tbody>{filteredComplaints.map((item) => <tr key={item.id}><td>{item.id}</td><td>{item.user_name}<div style={{ color: '#94a3b8', fontSize: 12 }}>{item.category}</div></td><td>{item.threat_type}</td><td><span className={getRiskBadgeClass(item.risk_level)}>{item.risk_level} · {item.risk_score}</span></td><td>{item.attack_channel || 'Unknown'}</td><td>{item.linked_case_count || 0}</td><td>{item.evidence_name ? <button onClick={() => openEvidence(item.id)} className="text-link" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>Open</button> : '-'}</td><td><select value={item.status} onChange={(e) => handleStatusChange(item.id, e.target.value)} style={inputStyle}>{statusOptions.map((status) => <option key={status}>{status}</option>)}</select></td><td>{item.created_at}</td></tr>)}</tbody></table></div>
        {evidenceError && <div style={{ color: '#fca5a5', marginTop: 8 }}>{evidenceError}</div>}
      </div>

      <div className="dashboard-grid" style={{ marginTop: 22 }}>
        <div className="panel"><div className="panel-header"><h2>Campaign Intelligence</h2></div>{graph?.nodes?.length ? <div className="graph-grid">{graph.nodes.map((node) => <div key={node.id} className={`graph-node ${node.kind}`}><div className="graph-kind">{node.kind}</div><div className="graph-label">{node.label}</div></div>)}<div className="graph-edge-list"><strong>Links</strong>{graph.edges.map((edge, i) => <div key={i} className="edge-item">{edge.source.slice(0, 18)} → {edge.target.slice(0, 18)} <span>{edge.label}</span></div>)}</div></div> : <p style={{ color: '#94a3b8' }}>No repeated campaign graph yet.</p>}</div>
        <div className="panel"><div className="panel-header"><h2>Recent Audit Trail</h2></div><div className="list-wrap">{auditLogs.map((log) => <div key={log.id} className="incident-card"><div className="incident-top"><strong>{log.action}</strong><span style={{ color: '#93c5fd', fontSize: 12 }}>{log.created_at}</span></div><p><strong>Actor:</strong> {log.actor_name || 'system'} ({log.actor_role || 'system'})</p><p><strong>Target:</strong> {log.target_type} {log.target_id || '-'}</p>{log.old_value || log.new_value ? <p><strong>Change:</strong> {log.old_value || '-'} → {log.new_value || '-'}</p> : null}{log.details ? <p><strong>Details:</strong> {log.details}</p> : null}</div>)}</div></div>
      </div>

      <div className="panel" style={{ marginTop: 22 }}><div className="panel-header"><h2>Registered Users</h2></div><div className="table-wrap"><table className="complaints-table"><thead><tr><th>Name</th><th>Email</th><th>Role</th><th>Created</th></tr></thead><tbody>{users.map((person) => <tr key={person.id}><td>{person.full_name}</td><td>{person.email}</td><td>{person.role}</td><td>{person.created_at}</td></tr>)}</tbody></table></div></div>
    </div>
  );
}

function StatCard({ label, value, tone }) { return <div className={`stat-card ${tone === 'critical' ? 'critical-border' : ''}`}><div className="stat-label">{label}</div><div className="stat-value">{value ?? 0}</div></div>; }

const inputStyle = { background: '#0f172a', color: 'white', border: '1px solid #334155', borderRadius: 10, padding: '10px 12px' };
const buttonStyle = { background: 'linear-gradient(135deg, #f59e0b, #f97316)', color: '#081120', border: 'none', borderRadius: 10, padding: '10px 14px', cursor: 'pointer', fontWeight: 700 };
