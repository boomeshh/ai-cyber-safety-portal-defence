import { useState } from "react";

function Login() {
  const [form, setForm] = useState({ email: "", password: "" });

  const handleLogin = async (e) => {
    e.preventDefault();

    try {
      const res = await fetch("http://127.0.0.1:8000/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form),
      });

      const data = await res.json();

      if (data.success) {
        localStorage.setItem("user", JSON.stringify(data.user));
        localStorage.setItem("token", data.token);
        window.location.href = "/dashboard";
      } else {
        alert(data.message);
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

        <h2 className="form-title">Secure User Login</h2>

        <form className="form" onSubmit={handleLogin}>
          <input
            type="email"
            placeholder="Enter email"
            value={form.email}
            onChange={(e) => setForm({ ...form, email: e.target.value })}
            required
          />

          <input
            type="password"
            placeholder="Enter password"
            value={form.password}
            onChange={(e) => setForm({ ...form, password: e.target.value })}
            required
          />

          <button className="btn" type="submit">Login</button>
        </form>

        <div className="link-text">
          New user?
          <span className="link-btn" onClick={() => (window.location.href = "/register")}>Register</span>
        </div>
      </div>
    </div>
  );
}

export default Login;
