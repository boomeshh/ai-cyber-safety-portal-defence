import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import "./App.css";

import AdminDashboard from "./pages/AdminDashboard";

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<AdminDashboard />} />
      </Routes>
    </Router>
  );
}

export default App;