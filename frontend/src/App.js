import React, { useState } from "react";
import Home from "./Home";
import Analysis from "./Analysis";
import AboutUs from "./AboutUs";
import Statistics from "./Statistics";
import logo from "./assets/vulnerability-ai-logo-v2.png";
import "./App.css";

function App() {
  const [page, setPage] = useState("home");
  const [menuOpen, setMenuOpen] = useState(false);

  function changePage(nextPage) {
    setPage(nextPage);
    setMenuOpen(false);
  }

  return (
    <div className="app">
      <nav className="navbar">
        <button
          className="nav-brand"
          onClick={() => changePage("home")}
          type="button"
        >
          <span className="nav-logo-image">
            <img src={logo} alt="" />
          </span>
          <span className="nav-brand-text">
            <strong>Code Vulnerability</strong>
            <small>Detector</small>
          </span>
        </button>

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
          <button
            className={page === "home" ? "active" : ""}
            onClick={() => changePage("home")}
          >
            Home
          </button>

          <button
            className={page === "analysis" ? "active" : ""}
            onClick={() => changePage("analysis")}
          >
            Analyze
          </button>

          <button
            className={page === "statistics" ? "active" : ""}
            onClick={() => changePage("statistics")}
          >
            Statistics
          </button>

          <button
            className={page === "about" ? "active" : ""}
            onClick={() => changePage("about")}
          >
            About
          </button>
        </div>
      </nav>

      {page === "home" && (
        <Home
          goToAnalyze={() => changePage("analysis")}
          goToAbout={() => changePage("about")}
        />
      )}

      {page === "analysis" && <Analysis />}

      {page === "about" && <AboutUs />}

      {page === "statistics" && <Statistics />}

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
