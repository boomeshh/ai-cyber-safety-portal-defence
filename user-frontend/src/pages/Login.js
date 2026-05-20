/**
 * Login.js — Rakshak AI user login with Firebase email verification.
 *
 * Flow:
 *   1. User enters email + password
 *   2. Firebase signInWithEmailAndPassword authenticates the credentials
 *   3. If email is NOT verified → show error, sign out of Firebase
 *   4. If email IS verified → call existing backend /login to get session token
 *   5. Store backend token + user in localStorage (unchanged from before)
 *   6. Navigate to /dashboard
 */

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

  // If already logged in (backend session), skip to dashboard
  useEffect(() => {
    const user = getStoredUser();
    if (user) navigate("/dashboard");
  }, [navigate]);

  const handleLogin = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      // Step 1 — Firebase authentication
      const credential = await signInWithEmailAndPassword(
        auth,
        form.email,
        form.password
      );
      const firebaseUser = credential.user;

      // Step 2 — Block unverified emails
      if (!firebaseUser.emailVerified) {
        await signOut(auth); // sign out of Firebase immediately
        setError(
          "Your email is not verified. Please check your inbox and click the verification link before logging in."
        );
        setLoading(false);
        return;
      }

      // Step 3 — Call existing backend /login for session token
      const res = await fetch(`${API}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: form.email, password: form.password }),
      });
      const data = await res.json();

      if (!data.success) {
        await signOut(auth);
        setError(data.message || "Login failed. Please try again.");
        setLoading(false);
        return;
      }

      // Step 4 — Store backend session (unchanged)
      localStorage.setItem("user", JSON.stringify(data.user));
      localStorage.setItem("token", data.token);
      navigate("/dashboard");

    } catch (err) {
      // Map Firebase error codes to friendly messages
      const code = err.code || "";
      if (code === "auth/user-not-found" || code === "auth/wrong-password" || code === "auth/invalid-credential") {
        setError("Invalid email or password.");
      } else if (code === "auth/too-many-requests") {
        setError("Too many failed attempts. Please try again later.");
      } else if (code === "auth/network-request-failed") {
        setError("Network error. Check your internet connection.");
      } else if (err.message?.includes("fetch")) {
        setError("Backend connection failed. Check if backend is running.");
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
          <h1>Rakshak AI</h1>
          <p>Cyber Safety Portal for Defence</p>
        </div>

        <h2 className="form-title">Secure User Login</h2>

        {error && (
          <div style={{
            background: "#1a0a0a", border: "1px solid #7f1d1d",
            borderRadius: 8, padding: "10px 14px", marginBottom: 14,
            color: "#fca5a5", fontSize: 13,
          }}>
            {error}
          </div>
        )}

        <form className="form" onSubmit={handleLogin}>
          <input
            type="email"
            placeholder="Enter email"
            value={form.email}
            onChange={(e) => { setForm({ ...form, email: e.target.value }); setError(""); }}
            required
          />
          <input
            type="password"
            placeholder="Enter password"
            value={form.password}
            onChange={(e) => { setForm({ ...form, password: e.target.value }); setError(""); }}
            required
          />
          <button className="btn" type="submit" disabled={loading}>
            {loading ? "Logging in..." : "Login"}
          </button>
        </form>

        <div className="link-text">
          New user?
          <span className="link-btn" onClick={() => navigate("/register")}>Register</span>
        </div>
      </div>
    </div>
  );
}
