/**
 * AuthContext.js — Firebase auth state provider for Rakshak AI.
 *
 * Wraps the app and exposes:
 *   firebaseUser  — current Firebase user (null if not signed in)
 *   authLoading   — true while Firebase resolves the initial auth state
 *
 * The existing backend session (localStorage token/user) is managed
 * separately in utils/auth.js and is unchanged.
 */

import { createContext, useContext, useEffect, useState } from "react";
import { onAuthStateChanged } from "firebase/auth";
import { auth } from "../firebase";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [firebaseUser, setFirebaseUser] = useState(undefined); // undefined = loading
  const [authLoading, setAuthLoading] = useState(true);

  useEffect(() => {
    const unsubscribe = onAuthStateChanged(auth, (user) => {
      setFirebaseUser(user);
      setAuthLoading(false);
    });
    return unsubscribe; // cleanup on unmount
  }, []);

  return (
    <AuthContext.Provider value={{ firebaseUser, authLoading }}>
      {children}
    </AuthContext.Provider>
  );
}

/** Hook — use inside any component to access Firebase auth state. */
export function useAuth() {
  return useContext(AuthContext);
}
