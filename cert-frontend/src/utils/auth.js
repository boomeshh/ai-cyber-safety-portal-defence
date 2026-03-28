export function getStoredUser() {
  try {
    return JSON.parse(localStorage.getItem('user') || 'null');
  } catch {
    return null;
  }
}

export function getToken() {
  return localStorage.getItem('token') || '';
}

export function getAuthHeaders(extra = {}) {
  const token = getToken();
  return {
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...extra,
  };
}

export function logoutUser() {
  localStorage.removeItem('token');
  localStorage.removeItem('user');
}
