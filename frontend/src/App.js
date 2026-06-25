import React, { useState } from "react";
import Home from "./Home";
import Analysis from "./Analysis";
import AboutUs from "./AboutUs";
import "./App.css";

function App() {
  const [page, setPage] = useState("home");

  return (
    <div className="app">
      <nav className="navbar">
        <div className="nav-logo">Code Vulnerability Detector</div>

        <div className="nav-menu">
          <button
            className={page === "home" ? "active" : ""}
            onClick={() => setPage("home")}
          >
            Home
          </button>

          <button
            className={page === "analysis" ? "active" : ""}
            onClick={() => setPage("analysis")}
          >
            Analyze
          </button>

          <button
            className={page === "about" ? "active" : ""}
            onClick={() => setPage("about")}
          >
            About
          </button>
        </div>

        
      </nav>

      {page === "home" && (
        <Home
          goToAnalyze={() => setPage("analysis")}
          goToAbout={() => setPage("about")}
        />
      )}

      {page === "analysis" && <Analysis />}

      {page === "about" && <AboutUs />}

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