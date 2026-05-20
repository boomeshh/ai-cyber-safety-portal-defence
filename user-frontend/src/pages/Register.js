/**
 * Register.js — Rakshak AI user registration with Firebase email verification.
 *
 * Flow:
 *   1. Validate form inputs client-side
 *   2. Call existing backend /register to create the user record
 *   3. Create Firebase account with same email + password
 *   4. Send Firebase verification email
 *   5. Sign out of Firebase (user must verify before logging in)
 *   6. Show success message and redirect to /verify-email
 */

import { useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  createUserWithEmailAndPassword,
  sendEmailVerification,
  signOut,
} from "firebase/auth";
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
      // Step 1 — Register with existing backend (creates user record + session)
      const res = await fetch(`${API}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          full_name: form.full_name,
          email: form.email,
          password: form.password,
        }),
      });
      const data = await res.json();

      if (!data.success) {
        setError(data.message || "Registration failed. Email may already be in use.");
        setLoading(false);
        return;
      }

      // Step 2 — Create Firebase account
      const credential = await createUserWithEmailAndPassword(
        auth,
        form.email,
        form.password
      );

      // Step 3 — Send verification email
      await sendEmailVerification(credential.user);

      // Step 4 — Sign out until email is verified
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
      } else if (err.message?.includes("fetch")) {
        setError("Backend connection failed. Check if backend is running.");
      } else {
        setError(err.message || "Registration failed. Please try again.");
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

        <h2 className="form-title">Secure Registration</h2>

        {error && (
          <div style={{
            background: "#1a0a0a", border: "1px solid #7f1d1d",
            borderRadius: 8, padding: "10px 14px", marginBottom: 14,
            color: "#fca5a5", fontSize: 13,
          }}>
            {error}
          </div>
        )}
        {success && (
          <div style={{
            background: "#0f2a1a", border: "1px solid #166534",
            borderRadius: 8, padding: "10px 14px", marginBottom: 14,
            color: "#4ade80", fontSize: 13,
          }}>
            {success}
          </div>
        )}

        <form className="form" onSubmit={handleRegister}>
          <input
            type="text"
            placeholder="Full name"
            value={form.full_name}
            onChange={(e) => { setForm({ ...form, full_name: e.target.value }); setError(""); }}
            required
          />
          <input
            type="email"
            placeholder="Email address"
            value={form.email}
            onChange={(e) => { setForm({ ...form, email: e.target.value }); setError(""); }}
            required
          />
          <input
            type="password"
            placeholder="Create password (min 6 chars)"
            minLength="6"
            value={form.password}
            onChange={(e) => { setForm({ ...form, password: e.target.value }); setError(""); }}
            required
          />
          <input
            type="password"
            placeholder="Confirm password"
            minLength="6"
            value={form.confirm_password}
            onChange={(e) => { setForm({ ...form, confirm_password: e.target.value }); setError(""); }}
            required
          />
          <button className="btn" type="submit" disabled={loading}>
            {loading ? "Creating account..." : "Create Account"}
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
