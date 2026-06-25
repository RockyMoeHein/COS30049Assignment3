import React from "react";

function About() {
  return (
    <main className="about-page">
      <section className="about-hero">
        <span className="project-badge">COS30049 Assignment 3</span>

        <h1>
          Code Vulnerability Detection <br />
          System
        </h1>

        <p>
          A machine learning web application project focused on detecting
          potential security vulnerabilities in source code and presenting the
          prediction result through a clear and user-friendly interface.
        </p>
      </section>

      <section className="about-section">
        <h2>Project Goals</h2>

        <div className="goal-grid">
          <div className="goal-card">
            <div className="goal-icon">🎯</div>
            <h3>Detect Vulnerable Code</h3>
            <p>
              Identify possible security weaknesses in source code using a
              trained machine learning model.
            </p>
          </div>

          <div className="goal-card">
            <div className="goal-icon">🤖</div>
            <h3>Apply Machine Learning</h3>
            <p>
              Use AI techniques to classify code as vulnerable or
              non-vulnerable based on learned patterns.
            </p>
          </div>

          <div className="goal-card">
            <div className="goal-icon">📊</div>
            <h3>Show Clear Results</h3>
            <p>
              Present prediction results, confidence scores, and vulnerability
              information in an easy-to-understand format.
            </p>
          </div>
        </div>
      </section>

      <section className="about-section">
        <h2>Core Technologies</h2>

        <div className="tech-grid">
          <div className="tech-card">
            <span className="small-icon">▣</span>
            <h3>Machine Learning</h3>
            <p>
              The AI model is trained using cybersecurity datasets containing
              vulnerable and non-vulnerable source code samples.
            </p>
          </div>

          <div className="tech-card">
            <span className="small-icon">⌁</span>
            <h3>Python</h3>
            <p>
              Python is used for model development, data processing, prediction
              logic, and backend integration.
            </p>
          </div>

          <div className="tech-card">
            <span className="small-icon">▥</span>
            <h3>Web Application</h3>
            <p>
              React.js provides a clean frontend interface for explaining the
              project and displaying analysis results.
            </p>
          </div>
        </div>
      </section>

      <section className="about-section">
        <h2>System Modules</h2>

        <div className="module-grid">
          <div className="module-card">
            <h3>Frontend Interface</h3>
            <p>
              Provides the web pages, navigation, input forms, visual layout,
              and user interaction using React.js.
            </p>
          </div>

          <div className="module-card">
            <h3>Backend API</h3>
            <p>
              Receives requests from the frontend and connects the web
              application to the prediction logic.
            </p>
          </div>

          <div className="module-card">
            <h3>AI Prediction Model</h3>
            <p>
              Analyzes submitted source code and predicts whether the code is
              safe or vulnerable.
            </p>
          </div>

          <div className="module-card">
            <h3>Result Visualization</h3>
            <p>
              Displays prediction output using result cards, confidence scores,
              and charts for better understanding.
            </p>
          </div>
        </div>
      </section>

      <section className="about-section">
        <h2>Research Team</h2>

        <div className="team-grid">
          <div className="team-card">
            <div className="avatar">👨‍💻</div>
            <h3>Frontend Developer</h3>
            <p>Responsible for About page design, layout, and styling.</p>
          </div>

          <div className="team-card">
            <div className="avatar">🧠</div>
            <h3>AI Model Developer</h3>
            <p>Responsible for model training and prediction logic.</p>
          </div>

          <div className="team-card">
            <div className="avatar">🛠️</div>
            <h3>Backend Developer</h3>
            <p>Responsible for FastAPI endpoints and API integration.</p>
          </div>
        </div>
      </section>
    </main>
  );
}

export default About;