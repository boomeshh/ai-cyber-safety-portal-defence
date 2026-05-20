import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { signInWithEmailAndPassword, signOut } from "firebase/auth";
import { auth } from "../firebase";
import { getStoredUser } from "../utils/auth";

const API = process.env.REACT_APP_API_BASE_URL || "https://ai-cyber-safety-portal-defence.onrender.com";

export default function Login() {
  const navigate = useNavigate();
  const [form, setForm] = useState({ email: "", password: "" });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const user = getStoredUser();
    if (user) navigate("/dashboard");
  }, [navigate]);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const credential = await signInWithEmailAndPassword(auth, form.email, form.password);
      const firebaseUser = credential.user;

      if (!firebaseUser.emailVerified) {
        await signOut(auth);
        setError("Your email is not verified. Please check your inbox and click the verification link before logging in.");
        setLoading(false);
        return;
      }

      let data;
      try {
        const res = await fetch(`${API}/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: form.email, password: form.password }),
        });
        data = await res.json();
      } catch {
        await signOut(auth);
        setError(`Cannot reach backend at ${API}. Check if the server is running.`);
        setLoading(false);
        return;
      }

      if (!data.success) {
        await signOut(auth);
        setError(data.message || "Login failed. Please try again.");
        setLoading(false);
        return;
      }

      localStorage.setItem("user", JSON.stringify(data.user));
      localStorage.setItem("token", data.token);
      navigate("/dashboard");

    } catch (err) {
      const code = err.code || "";
      if (code === "auth/user-not-found" || code === "auth/wrong-password" || code === "auth/invalid-credential") {
        setError("Invalid email or password.");
      } else if (code === "auth/too-many-requests") {
        setError("Too many failed attempts. Please try again later.");
      } else if (code === "auth/network-request-failed") {
        setError("Network error. Check your internet connection.");
      } else {
        setError(err.message || "Login failed. Please try again.");
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="page">
      <div className="card">
        <div className="brand">
          <div className="brand-icon">🛡️</div>
          <h1>Rakshak AI</h1>
          <p>Defence Cyber Safety Portal</p>
        </div>

        <h2 className="form-title">Secure Login</h2>

        {error && (
          <div className="alert-banner error" style={{ marginBottom: 18 }}>
            <span>⚠</span> {error}
          </div>
        )}

        <form className="form" onSubmit={handleLogin}>
          <input
            type="email"
            placeholder="Defence email address"
            value={form.email}
            autoComplete="email"
            onChange={(e) => { setForm({ ...form, email: e.target.value }); setError(""); }}
            required
          />
          <input
            type="password"
            placeholder="Password"
            value={form.password}
            autoComplete="current-password"
            onChange={(e) => { setForm({ ...form, password: e.target.value }); setError(""); }}
            required
          />
          <button className="btn" type="submit" disabled={loading} style={{ marginTop: 4 }}>
            {loading ? <><span className="spinner" /> Authenticating...</> : "🔐 Login"}
          </button>
        </form>

        <div className="link-text">
          New user?
          <span className="link-btn" onClick={() => navigate("/register")}>Create Account</span>
        </div>

        <div style={{ marginTop: 20, padding: '10px 14px', background: 'rgba(56,189,248,0.05)', border: '1px solid rgba(56,189,248,0.12)', borderRadius: 10, textAlign: 'center' }}>
          <span style={{ color: '#64748b', fontSize: 12 }}>
            <span className="status-dot online" />
            Secured by Firebase Authentication · AES-256 Encrypted
          </span>
        </div>
      </div>
    </div>
  );
}
