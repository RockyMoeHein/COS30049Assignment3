import React, { useEffect, useState } from "react";
import {
  Navigate,
  NavLink,
  Route,
  Routes,
  useLocation,
  useNavigate,
} from "react-router-dom";
import Home from "./Home";
import Analysis from "./Analysis";
import AboutUs from "./AboutUs";
import Statistics from "./Statistics";
import logo from "./assets/vulnerability-ai-logo-v2.png";
import "./App.css";

function App() {
  const [menuOpen, setMenuOpen] = useState(false);
  const location = useLocation();
  const navigate = useNavigate();

  // Reset scroll position when moving between pages.
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [location.pathname]);

  // Used by Home page buttons so navigation also closes the mobile menu.
  function changePage(path) {
    navigate(path);
    setMenuOpen(false);
  }

  return (
    <div className="app">
      <nav className="navbar">
        <NavLink
          className="nav-brand"
          onClick={() => setMenuOpen(false)}
          to="/"
        >
          <span className="nav-logo-image">
            <img src={logo} alt="" />
          </span>
          <span className="nav-brand-text">
            <strong>Code Vulnerability</strong>
            <small>Detector</small>
          </span>
        </NavLink>

        <button
          aria-expanded={menuOpen}
          aria-label={menuOpen ? "Close navigation menu" : "Open navigation menu"}
          className={`nav-toggle ${menuOpen ? "is-open" : ""}`}
          onClick={() => setMenuOpen((isOpen) => !isOpen)}
          type="button"
        >
          <span />
          <span />
          <span />
        </button>

        <div className={`nav-menu ${menuOpen ? "is-open" : ""}`}>
          <NavLink end onClick={() => setMenuOpen(false)} to="/">
            Home
          </NavLink>

          <NavLink onClick={() => setMenuOpen(false)} to="/analysis">
            Analyze
          </NavLink>

          <NavLink onClick={() => setMenuOpen(false)} to="/statistics">
            Statistics
          </NavLink>

          <NavLink onClick={() => setMenuOpen(false)} to="/about">
            About
          </NavLink>
        </div>
      </nav>

      <Routes>
        <Route
          path="/"
          element={(
            <Home
              goToAnalyze={() => changePage("/analysis")}
              goToAbout={() => changePage("/about")}
            />
          )}
        />
        <Route path="/analysis" element={<Analysis />} />
        <Route path="/statistics" element={<Statistics />} />
        <Route path="/about" element={<AboutUs />} />
        <Route path="*" element={<Navigate replace to="/" />} />
      </Routes>

      <footer className="footer">
        <div className="footer-brand">
          <strong>COS30049 Assignment 3</strong>
        </div>

        <p>Machine Learning Web Application Group Project</p>

        <div className="footer-links">
          <span>React Frontend</span>
          <span>FastAPI Backend</span>
          <span>AI Model</span>
          <span>2026</span>
        </div>
      </footer>
    </div>
  );
}

export default App;
