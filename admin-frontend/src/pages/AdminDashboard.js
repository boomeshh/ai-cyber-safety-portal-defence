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

// ─── Phase A: Complaint Detail Panel ────────────────────────────────────────
function ComplaintDetailPanel({ item, onClose }) {
  const [tab, setTab] = useState('timeline');
  const [timeline, setTimeline] = useState(null);
  const [notes, setNotes] = useState([]);
  const [newNote, setNewNote] = useState('');
  const [feedback, setFeedback] = useState([]);
  const [verdict, setVerdict] = useState('correct');
  const [comment, setComment] = useState('');
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState('');

  useEffect(() => {
    if (tab === 'timeline' && !timeline) {
      fetch(`${API}/admin/complaints/${item.id}/timeline`, { headers: getAuthHeaders() })
        .then(r => r.json()).then(d => setTimeline(d.timeline || [])).catch(() => setTimeline([]));
    }
    if (tab === 'notes') {
      fetch(`${API}/admin/complaints/${item.id}/notes`, { headers: getAuthHeaders() })
        .then(r => r.json()).then(d => setNotes(Array.isArray(d) ? d : [])).catch(() => {});
    }
    if (tab === 'feedback') {
      fetch(`${API}/admin/complaints/${item.id}/feedback`, { headers: getAuthHeaders() })
        .then(r => r.json()).then(d => setFeedback(Array.isArray(d) ? d : [])).catch(() => {});
    }
  }, [tab, item.id, timeline]);

  const addNote = async () => {
    if (!newNote.trim()) return;
    setSaving(true); setMsg('');
    try {
      const res = await fetch(`${API}/admin/complaints/${item.id}/notes`, {
        method: 'POST', headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ note: newNote.trim() }),
      });
      const d = await res.json();
      if (d.success) { setNotes(prev => [...prev, d]); setNewNote(''); setMsg('Note saved.'); }
    } catch { setMsg('Failed to save note.'); } finally { setSaving(false); }
  };

  const addFeedback = async () => {
    setSaving(true); setMsg('');
    try {
      const res = await fetch(`${API}/admin/complaints/${item.id}/feedback`, {
        method: 'POST', headers: { ...getAuthHeaders(), 'Content-Type': 'application/json' },
        body: JSON.stringify({ verdict, comment: comment || null }),
      });
      const d = await res.json();
      if (d.success) { setFeedback(prev => [...prev, d]); setComment(''); setMsg('Feedback recorded.'); }
    } catch { setMsg('Failed to save feedback.'); } finally { setSaving(false); }
  };

  const tabStyle = (t) => ({
    padding: '6px 14px', borderRadius: 8, cursor: 'pointer', fontSize: 13, fontWeight: 600,
    background: tab === t ? '#1e40af' : '#1e293b', color: tab === t ? '#fff' : '#94a3b8', border: 'none',
  });

  return (
    <div style={{ background: '#0b1220', border: '1px solid #1e293b', borderRadius: 14, padding: 20, marginTop: 8 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 14 }}>
        <strong style={{ color: '#e2e8f0' }}>Case Detail: {item.id}</strong>
        <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', fontSize: 18 }}>✕</button>
      </div>

      {/* Phase B — Severity Explanation */}
      {item.severity_explanation ? (
        <div style={{ background: '#1e1a0f', border: '1px solid #854d0e', borderRadius: 10, padding: '10px 14px', marginBottom: 12 }}>
          <div style={{ color: '#fbbf24', fontWeight: 700, fontSize: 13 }}>⚠ Why this risk level?</div>
          <div style={{ color: '#fde68a', fontSize: 13, marginTop: 4 }}>{item.severity_explanation.summary}</div>
          <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 4 }}>Score: {item.severity_explanation.risk_score} ({item.severity_explanation.score_band}) · Confidence: {item.severity_explanation.ai_confidence_pct}%</div>
        </div>
      ) : null}

      {/* Phase B — IOC Panel */}
      {item.ioc && (item.ioc.urls?.length > 0 || item.ioc.emails?.length > 0 || item.ioc.phones?.length > 0) ? (
        <div style={{ background: '#1a0f1e', border: '1px solid #6b21a8', borderRadius: 10, padding: '10px 14px', marginBottom: 12 }}>
          <div style={{ color: '#c084fc', fontWeight: 700, fontSize: 13 }}>🔍 Extracted IOCs</div>
          {item.ioc.urls?.length > 0 ? <div style={{ marginTop: 4, fontSize: 12, color: '#a78bfa' }}>URLs: {item.ioc.urls.join(', ')}</div> : null}
          {item.ioc.emails?.length > 0 ? <div style={{ marginTop: 2, fontSize: 12, color: '#a78bfa' }}>Emails: {item.ioc.emails.join(', ')}</div> : null}
          {item.ioc.phones?.length > 0 ? <div style={{ marginTop: 2, fontSize: 12, color: '#a78bfa' }}>Phones: {item.ioc.phones.join(', ')}</div> : null}
        </div>
      ) : null}

      {/* Phase B — Mitigation Steps */}
      {Array.isArray(item.mitigation_steps) && item.mitigation_steps.length > 0 ? (
        <div style={{ background: '#0f2a1a', border: '1px solid #166534', borderRadius: 10, padding: '10px 14px', marginBottom: 12 }}>
          <div style={{ color: '#4ade80', fontWeight: 700, fontSize: 13 }}>✅ Mitigation Steps</div>
          <ol style={{ marginTop: 6, paddingLeft: 18, color: '#86efac', fontSize: 12 }}>
            {item.mitigation_steps.map((s, i) => <li key={i} style={{ marginBottom: 3 }}>{s}</li>)}
          </ol>
        </div>
      ) : null}

      {/* Phase A — Tabs */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 14, flexWrap: 'wrap' }}>
        <button style={tabStyle('timeline')} onClick={() => setTab('timeline')}>Timeline</button>
        <button style={tabStyle('notes')} onClick={() => setTab('notes')}>Notes</button>
        <button style={tabStyle('feedback')} onClick={() => setTab('feedback')}>AI Feedback</button>
      </div>

      {msg ? <div style={{ color: '#4ade80', fontSize: 13, marginBottom: 8 }}>{msg}</div> : null}

      {tab === 'timeline' && (
        <div>
          {!timeline ? <div style={{ color: '#94a3b8', fontSize: 13 }}>Loading...</div> :
            timeline.length === 0 ? <div style={{ color: '#94a3b8', fontSize: 13 }}>No timeline events.</div> :
            <div style={{ position: 'relative', paddingLeft: 20 }}>
              {timeline.map((ev, i) => (
                <div key={i} style={{ marginBottom: 12, position: 'relative' }}>
                  <div style={{ position: 'absolute', left: -14, top: 4, width: 8, height: 8, borderRadius: '50%', background: '#38bdf8' }} />
                  <div style={{ color: '#e2e8f0', fontWeight: 600, fontSize: 13 }}>{ev.event}</div>
                  <div style={{ color: '#94a3b8', fontSize: 12 }}>{ev.description}</div>
                  <div style={{ color: '#475569', fontSize: 11 }}>{ev.actor} · {ev.created_at}</div>
                </div>
              ))}
            </div>
          }
        </div>
      )}

      {tab === 'notes' && (
        <div>
          <div style={{ marginBottom: 10 }}>
            {notes.length === 0 ? <div style={{ color: '#94a3b8', fontSize: 13 }}>No notes yet.</div> :
              notes.map((n, i) => (
                <div key={i} style={{ background: '#1e293b', borderRadius: 8, padding: '8px 12px', marginBottom: 8 }}>
                  <div style={{ color: '#e2e8f0', fontSize: 13 }}>{n.note}</div>
                  <div style={{ color: '#475569', fontSize: 11, marginTop: 4 }}>{n.actor_name} ({n.actor_role}) · {n.created_at}</div>
                </div>
              ))
            }
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <input value={newNote} onChange={e => setNewNote(e.target.value)} placeholder="Add internal note..."
              style={{ flex: 1, background: '#0f172a', color: '#e2e8f0', border: '1px solid #334155', borderRadius: 8, padding: '8px 12px', fontSize: 13 }} />
            <button onClick={addNote} disabled={saving} style={{ ...buttonStyle, padding: '8px 14px', fontSize: 13 }}>
              {saving ? '...' : 'Add'}
            </button>
          </div>
        </div>
      )}

      {tab === 'feedback' && (
        <div>
          <div style={{ marginBottom: 10 }}>
            {feedback.length === 0 ? <div style={{ color: '#94a3b8', fontSize: 13 }}>No feedback yet.</div> :
              feedback.map((f, i) => (
                <div key={i} style={{ background: '#1e293b', borderRadius: 8, padding: '8px 12px', marginBottom: 8 }}>
                  <div style={{ color: '#e2e8f0', fontSize: 13, fontWeight: 600 }}>{f.verdict}</div>
                  {f.comment ? <div style={{ color: '#94a3b8', fontSize: 12 }}>{f.comment}</div> : null}
                  <div style={{ color: '#475569', fontSize: 11, marginTop: 4 }}>{f.actor_name} · {f.created_at}</div>
                </div>
              ))
            }
          </div>
          <div style={{ display: 'grid', gap: 8 }}>
            <select value={verdict} onChange={e => setVerdict(e.target.value)} style={inputStyle}>
              <option value="correct">Correct</option>
              <option value="wrong_classification">Wrong Classification</option>
              <option value="needs_review">Needs Review</option>
            </select>
            <input value={comment} onChange={e => setComment(e.target.value)} placeholder="Optional comment..."
              style={{ background: '#0f172a', color: '#e2e8f0', border: '1px solid #334155', borderRadius: 8, padding: '8px 12px', fontSize: 13 }} />
            <button onClick={addFeedback} disabled={saving} style={{ ...buttonStyle, padding: '8px 14px', fontSize: 13 }}>
              {saving ? 'Saving...' : 'Submit Feedback'}
            </button>
          </div>
        </div>
      )}
    </div>
  );
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
  const [expandedId, setExpandedId] = useState(null);

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
        <div className="table-wrap"><table className="complaints-table"><thead><tr><th>ID</th><th>User</th><th>Threat</th><th>Risk</th><th>Channel</th><th>Linked</th><th>Evidence</th><th>Status</th><th>Date</th><th>Detail</th></tr></thead><tbody>{filteredComplaints.map((item) => (<>
          <tr key={item.id}><td>{item.id}</td><td>{item.user_name}<div style={{ color: '#94a3b8', fontSize: 12 }}>{item.category}</div></td><td>{item.threat_type}</td><td><span className={getRiskBadgeClass(item.risk_level)}>{item.risk_level} · {item.risk_score}</span></td><td>{item.attack_channel || 'Unknown'}</td><td>{item.linked_case_count || 0}</td><td>{item.evidence_name ? <button onClick={() => openEvidence(item.id)} className="text-link" style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>Open</button> : '-'}</td><td><select value={item.status} onChange={(e) => handleStatusChange(item.id, e.target.value)} style={inputStyle}>{statusOptions.map((status) => <option key={status}>{status}</option>)}</select></td><td>{item.created_at}</td>
          <td><button onClick={() => setExpandedId(expandedId === item.id ? null : item.id)} style={{ background: 'none', border: '1px solid #334155', borderRadius: 6, color: '#94a3b8', cursor: 'pointer', padding: '4px 8px', fontSize: 12 }}>{expandedId === item.id ? '▲' : '▼'}</button></td></tr>
          {expandedId === item.id ? (
            <tr key={`${item.id}-detail`}><td colSpan={10} style={{ padding: '0 8px 12px' }}>
              <ComplaintDetailPanel item={item} onClose={() => setExpandedId(null)} />
            </td></tr>
          ) : null}
        </>))}</tbody></table></div>
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
