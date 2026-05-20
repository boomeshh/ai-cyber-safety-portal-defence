import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { createUserWithEmailAndPassword, sendEmailVerification, signOut } from "firebase/auth";
import { auth } from "../firebase";

const API = process.env.REACT_APP_API_BASE_URL || "https://ai-cyber-safety-portal-defence.onrender.com";

export default function Register() {
  const navigate = useNavigate();
  const [form, setForm] = useState({ full_name: "", email: "", password: "", confirm_password: "" });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const validate = () => {
    if (!form.full_name.trim()) return "Full name is required.";
    if (!form.email.trim()) return "Email is required.";
    if (form.password.length < 6) return "Password must be at least 6 characters.";
    if (form.password !== form.confirm_password) return "Passwords do not match.";
    return null;
  };

  const handleRegister = async (e) => {
    e.preventDefault();
    setError(""); setSuccess("");
    const validationError = validate();
    if (validationError) { setError(validationError); return; }
    setLoading(true);

    try {
      let data;
      try {
        const res = await fetch(`${API}/register`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ full_name: form.full_name, email: form.email, password: form.password }),
        });
        data = await res.json();
      } catch {
        setError(`Cannot reach backend at ${API}. Check if the server is running.`);
        setLoading(false);
        return;
      }

      if (!data.success) {
        setError(data.message || "Registration failed. Email may already be in use.");
        setLoading(false);
        return;
      }

      const credential = await createUserWithEmailAndPassword(auth, form.email, form.password);
      await sendEmailVerification(credential.user);
      await signOut(auth);

      setSuccess("Account created! A verification email has been sent. Please verify before logging in.");
      setTimeout(() => navigate("/verify-email"), 2000);

    } catch (err) {
      const code = err.code || "";
      if (code === "auth/email-already-in-use") {
        setError("This email is already registered. Please log in.");
      } else if (code === "auth/weak-password") {
        setError("Password is too weak. Use at least 6 characters.");
      } else if (code === "auth/invalid-email") {
        setError("Invalid email address.");
      } else if (code === "auth/network-request-failed") {
        setError("Network error. Check your internet connection.");
      } else {
        setError(err.message || "Registration failed. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  };

  const strength = form.password.length === 0 ? 0 : form.password.length < 6 ? 1 : form.password.length < 10 ? 2 : 3;
  const strengthLabel = ["", "Weak", "Good", "Strong"][strength];
  const strengthColor = ["", "#ef4444", "#eab308", "#22c55e"][strength];

  return (
    <div className="page">
      <div className="card">
        <div className="brand">
          <div className="brand-icon">🛡️</div>
          <h1>Rakshak AI</h1>
          <p>Defence Cyber Safety Portal</p>
        </div>

        <h2 className="form-title">Create Account</h2>

        {error && (
          <div className="alert-banner error" style={{ marginBottom: 16 }}>
            <span>⚠</span> {error}
          </div>
        )}
        {success && (
          <div className="alert-banner success" style={{ marginBottom: 16 }}>
            <span>✓</span> {success}
          </div>
        )}

        <form className="form" onSubmit={handleRegister}>
          <input
            type="text"
            placeholder="Full name"
            value={form.full_name}
            autoComplete="name"
            onChange={(e) => { setForm({ ...form, full_name: e.target.value }); setError(""); }}
            required
          />
          <input
            type="email"
            placeholder="Email address"
            value={form.email}
            autoComplete="email"
            onChange={(e) => { setForm({ ...form, email: e.target.value }); setError(""); }}
            required
          />
          <div>
            <input
              type="password"
              placeholder="Create password (min 6 chars)"
              minLength="6"
              value={form.password}
              autoComplete="new-password"
              onChange={(e) => { setForm({ ...form, password: e.target.value }); setError(""); }}
              required
              style={{ marginBottom: form.password ? 6 : 0 }}
            />
            {form.password.length > 0 && (
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 4 }}>
                <div style={{ flex: 1, height: 3, borderRadius: 99, background: '#1e293b', overflow: 'hidden' }}>
                  <div style={{ width: `${(strength / 3) * 100}%`, height: '100%', background: strengthColor, transition: 'width 0.3s, background 0.3s', borderRadius: 99 }} />
                </div>
                <span style={{ fontSize: 11, color: strengthColor, fontWeight: 600, minWidth: 40 }}>{strengthLabel}</span>
              </div>
            )}
          </div>
          <input
            type="password"
            placeholder="Confirm password"
            minLength="6"
            value={form.confirm_password}
            autoComplete="new-password"
            onChange={(e) => { setForm({ ...form, confirm_password: e.target.value }); setError(""); }}
            required
          />
          <button className="btn" type="submit" disabled={loading} style={{ marginTop: 4 }}>
            {loading ? <><span className="spinner" /> Creating account...</> : "🔐 Create Account"}
          </button>
        </form>

        <div className="link-text">
          Already have an account?
          <span className="link-btn" onClick={() => navigate("/")}>Login</span>
        </div>
      </div>
    </div>
  );
}
