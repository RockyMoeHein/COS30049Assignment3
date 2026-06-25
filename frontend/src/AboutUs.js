import React from "react";
import "./AboutUs.css";
import khantPhoto from "./assets/khantthu.jpg";
import zinPhoto from "./assets/zinko.png";
import sawPhoto from "./assets/sawnay.jpg";

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
            <div className="goal-icon">01</div>
            <h3>Detect Vulnerable Code</h3>
            <p>
              Identify possible security weaknesses in source code using a
              trained machine learning model.
            </p>
          </div>

          <div className="goal-card">
            <div className="goal-icon">02</div>
            <h3>Apply Machine Learning</h3>
            <p>
              Use AI techniques to classify code as vulnerable or
              non-vulnerable based on learned patterns.
            </p>
          </div>

          <div className="goal-card">
            <div className="goal-icon">03</div>
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
            <span className="small-icon">ML</span>
            <h3>Machine Learning</h3>
            <p>
              The AI model is trained using cybersecurity datasets containing
              vulnerable and non-vulnerable source code samples.
            </p>
          </div>

          <div className="tech-card">
            <span className="small-icon">PY</span>
            <h3>Python</h3>
            <p>
              Python is used for model development, data processing, prediction
              logic, and backend integration.
            </p>
          </div>

          <div className="tech-card">
            <span className="small-icon">UI</span>
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
        <h2>Team</h2>

        <div className="team-grid">
          <div className="team-card">
            <img
              className="avatar"
              src={khantPhoto}
              alt="Khant Thu Aung"
            />
            <h3>Khant Thu Aung</h3>
            <span className="team-role">Backend Integration</span>
            <p>
              Developed the backend integration and worked with Zin Ko Oo to
              connect the frontend to the API and display model predictions.
            </p>
          </div>

          <div className="team-card">
            <img
              className="avatar"
              src={zinPhoto}
              alt="Zin Ko Oo"
            />
            <h3>Zin Ko Oo</h3>
            <span className="team-role">Frontend and Analysis UI</span>
            <p>
              Designed and developed the Home and Analysis pages, and worked
              with Khant Thu Aung to connect model outputs to the frontend.
            </p>
          </div>

          <div className="team-card">
            <img
              className="avatar"
              src={sawPhoto}
              alt="Saw Nay Wun"
            />
            <h3>Saw Nay Wun</h3>
            <span className="team-role">Visualization and About UI</span>
            <p>
              Developed the About Us and Statistics pages, including dataset
              visualizations, with additional contributions across the project.
            </p>
          </div>
        </div>
      </section>
    </main>
  );
}

export default About;
