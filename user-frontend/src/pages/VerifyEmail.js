/**
 * VerifyEmail.js — Shown after signup or when a user tries to access a
 * protected route without a verified email.
 *
 * Allows the user to:
 *   - Resend the verification email
 *   - Reload to check if they have verified
 *   - Sign out and go back to login
 */

import { useState, useEffect } from "react";
import { sendEmailVerification, signOut, reload, onAuthStateChanged } from "firebase/auth";
import { auth } from "../firebase";
import { logoutUser } from "../utils/auth";
import { useNavigate } from "react-router-dom";

export default function VerifyEmail() {
  const navigate = useNavigate();
  const [msg, setMsg] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);
  const [sessionLoading, setSessionLoading] = useState(true);

  // Wait for Firebase to resolve auth state before showing actions
  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (user) => {
      setCurrentUser(user);
      setSessionLoading(false);
      // If user is already verified, go straight to dashboard
      if (user?.emailVerified) {
        navigate("/dashboard");
      }
    });
    return unsubscribe;
  }, [navigate]);

  const resendVerification = async () => {
    setMsg(""); setError(""); setLoading(true);
    try {
      const user = auth.currentUser || currentUser;
      if (!user) {
        setError("Session expired. Please register again.");
        return;
      }
      await sendEmailVerification(user);
      setMsg("Verification email sent! Check your inbox and spam/junk folder.");
    } catch (err) {
      if (err.code === "auth/too-many-requests") {
        setError("Too many requests. Please wait a few minutes before resending.");
      } else {
        setError(err.message || "Failed to send verification email.");
      }
    } finally {
      setLoading(false);
    }
  };

  const checkVerified = async () => {
    setMsg(""); setError(""); setLoading(true);
    try {
      const user = auth.currentUser || currentUser;
      if (!user) {
        setError("Session expired. Please log in again.");
        navigate("/");
        return;
      }
      await reload(user);
      if (user.emailVerified) {
        setMsg("Email verified! Redirecting to dashboard...");
        setTimeout(() => navigate("/dashboard"), 1000);
      } else {
        setError("Email not verified yet. Please click the link in your inbox, then try again.");
      }
    } catch (err) {
      setError(err.message || "Could not check verification status.");
    } finally {
      setLoading(false);
    }
  };

  const handleSignOut = async () => {
    await signOut(auth);
    await logoutUser();
    navigate("/");
  };

  if (sessionLoading) {
    return (
      <div className="page">
        <div className="card" style={{ textAlign: "center" }}>
          <p style={{ color: "#94a3b8" }}>Loading session...</p>
        </div>
      </div>
    );
  }

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
