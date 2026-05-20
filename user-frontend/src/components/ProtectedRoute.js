/**
 * ProtectedRoute.js — Guards routes that require a verified Firebase user.
 *
 * Behaviour:
 *   - While Firebase resolves auth state → show loading spinner
 *   - No Firebase user → redirect to /
 *   - Firebase user but email NOT verified → redirect to /verify-email
 *   - Firebase user with verified email → render children
 *
 * The existing backend token check (getStoredUser) is preserved inside
 * each page component and is not replaced by this guard.
 */

import { Navigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function ProtectedRoute({ children }) {
  const { firebaseUser, authLoading } = useAuth();

  if (authLoading) {
    return (
      <div className="page">
        <div className="card" style={{ textAlign: "center" }}>
          <p style={{ color: "#94a3b8" }}>Verifying session...</p>
        </div>
      </div>
    );
  }

  if (!firebaseUser) {
    return <Navigate to="/" replace />;
  }

  if (!firebaseUser.emailVerified) {
    return <Navigate to="/verify-email" replace />;
  }

  return children;
}
