import React from "react";
import About from "./About";
import "./App.css";

function App() {
  return (
    <div className="app">
      <nav className="navbar">
        <div className="nav-logo">Code Vulnerability Detector</div>

        <div className="nav-menu">
          <button>Home</button>
          <button>Analyze</button>
          <button className="active">About</button>
        </div>

        <div></div>
      </nav>

      <About />

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