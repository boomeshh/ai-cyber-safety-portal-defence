import { useState } from "react";

const API = process.env.REACT_APP_API_BASE_URL || "http://localhost:8000";

function Register() {
  const [form, setForm] = useState({ full_name: "", email: "", password: "" });

  const handleRegister = async (e) => {
    e.preventDefault();

    try {
      const res = await fetch(`${API}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });

      const data = await res.json();
      alert(data.message);
      if (data.success) {
        window.location.href = "/";
      }
    } catch (error) {
      alert("Backend connection failed. Check if backend is running on port 8000.");
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

        <form className="form" onSubmit={handleRegister}>
          <input
            type="text"
            placeholder="Full name"
            value={form.full_name}
            onChange={(e) => setForm({ ...form, full_name: e.target.value })}
            required
          />

          <input
            type="email"
            placeholder="Email address"
            value={form.email}
            onChange={(e) => setForm({ ...form, email: e.target.value })}
            required
          />

          <input
            type="password"
            placeholder="Create password"
            minLength="6"
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            required
          />

          <button className="btn" type="submit">Create Account</button>
        </form>

        <div className="link-text">
          Already have an account?
          <span className="link-btn" onClick={() => (window.location.href = "/")}>Login</span>
        </div>
      </div>
    </div>
  );
}

export default Register;
