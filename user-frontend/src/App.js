import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import "./App.css";

import { AuthProvider } from "./context/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";

import Login from "./pages/Login";
import Register from "./pages/Register";
import VerifyEmail from "./pages/VerifyEmail";
import Dashboard from "./pages/Dashboard";
import SubmitComplaint from "./pages/SubmitComplaint";
import MyComplaints from "./pages/MyComplaints";
import PublicAwareness from "./pages/PublicAwareness";

function App() {
  return (
    <AuthProvider>
      <Router>
        <Routes>
          {/* Public routes — no auth required */}
          <Route path="/"              element={<Login />} />
          <Route path="/register"      element={<Register />} />
          <Route path="/verify-email"  element={<VerifyEmail />} />
          <Route path="/awareness"     element={<PublicAwareness />} />

          {/* Protected routes — require verified Firebase email */}
          <Route path="/dashboard"     element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
          <Route path="/submit"        element={<ProtectedRoute><SubmitComplaint /></ProtectedRoute>} />
          <Route path="/my-complaints" element={<ProtectedRoute><MyComplaints /></ProtectedRoute>} />
        </Routes>
      </Router>
    </AuthProvider>
  );
}

export default App;
