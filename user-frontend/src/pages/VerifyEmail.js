/**
 * VerifyEmail.js — Shown after signup or when a user tries to access a
 * protected route without a verified email.
 *
 * Allows the user to:
 *   - Resend the verification email
 *   - Reload to check if they have verified
 *   - Sign out and go back to login
 */

import { useState } from "react";
import { sendEmailVerification, signOut, reload } from "firebase/auth";
import { auth } from "../firebase";
import { logoutUser } from "../utils/auth";
import { useNavigate } from "react-router-dom";

export default function VerifyEmail() {
  const navigate = useNavigate();
  const [msg, setMsg] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const resendVerification = async () => {
    setMsg(""); setError(""); setLoading(true);
    try {
      const user = auth.currentUser;
      if (!user) { setError("No active session. Please log in again."); return; }
      await sendEmailVerification(user);
      setMsg("Verification email sent. Please check your inbox and spam folder.");
    } catch (err) {
      setError(err.message || "Failed to send verification email.");
    } finally {
      setLoading(false);
    }
  };

  const checkVerified = async () => {
    setMsg(""); setError(""); setLoading(true);
    try {
      const user = auth.currentUser;
      if (!user) { setError("No active session."); return; }
      await reload(user); // refresh Firebase user state
      if (user.emailVerified) {
        setMsg("Email verified! Redirecting...");
        setTimeout(() => navigate("/dashboard"), 1000);
      } else {
        setError("Email not verified yet. Please check your inbox.");
      }
    } catch (err) {
      setError(err.message || "Could not check verification status.");
    } finally {
      setLoading(false);
    }
  };

  const handleSignOut = async () => {
    await signOut(auth);
    logoutUser(); // clear backend session too
    navigate("/");
  };

  return (
    <div className="page">
      <div className="card">
        <div className="brand">
          <h1>Rakshak AI</h1>
          <p>Cyber Safety Portal for Defence</p>
        </div>

        <h2 className="form-title">Verify Your Email</h2>

        <p style={{ color: "#94a3b8", marginBottom: 20, textAlign: "center", fontSize: 14 }}>
          A verification link has been sent to your email address.
          Please verify your email before accessing the portal.
        </p>

        {msg   && <div style={{ color: "#4ade80", marginBottom: 12, fontSize: 13, textAlign: "center" }}>{msg}</div>}
        {error && <div style={{ color: "#fca5a5", marginBottom: 12, fontSize: 13, textAlign: "center" }}>{error}</div>}

        <div className="form" style={{ gap: 12 }}>
          <button className="btn" onClick={checkVerified} disabled={loading}>
            {loading ? "Checking..." : "I have verified — Continue"}
          </button>

          <button
            className="btn"
            style={{ background: "#1e293b" }}
            onClick={resendVerification}
            disabled={loading}
          >
            Resend Verification Email
          </button>

          <button
            className="btn"
            style={{ background: "#334155" }}
            onClick={handleSignOut}
          >
            Sign Out
          </button>
        </div>
      </div>
    </div>
  );
}
