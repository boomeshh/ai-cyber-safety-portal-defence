/**
 * auth.js — Backend session helpers for Rakshak AI.
 *
 * These functions manage the backend JWT token stored in localStorage.
 * Firebase auth state is managed separately via AuthContext.
 *
 * logoutUser() now also signs out of Firebase so both sessions are cleared.
 */

import { signOut } from "firebase/auth";
import { auth } from "../firebase";

export function getStoredUser() {
  try {
    return JSON.parse(localStorage.getItem("user") || "null");
  } catch {
    return null;
  }
}

export function getToken() {
  return localStorage.getItem("token") || "";
}

export function getAuthHeaders(extra = {}) {
  const token = getToken();
  return {
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...extra,
  };
}

/** Clears both the backend session and the Firebase session. */
export async function logoutUser() {
  localStorage.removeItem("token");
  localStorage.removeItem("user");
  try {
    await signOut(auth);
  } catch {
    // Firebase sign-out failure is non-critical
  }
}
