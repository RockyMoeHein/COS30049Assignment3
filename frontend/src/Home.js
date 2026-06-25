import React from "react";
import "./Home.css";

function Home({ goToAnalyze, goToAbout }) {
  return (
    <main className="home-page">
      {/* HERO SECTION */}
      <section className="home-hero">
        <div className="home-hero-left">
          <span className="home-badge">
            <span className="home-dot"></span>
            C VULNERABILITY MODEL READY
          </span>

          <h1>
            Detect Risky C Code <br />
            with Machine Learning
          </h1>

          <p>
            This web application uses our trained Assignment 2 model to predict
            whether a C source-code snippet is vulnerable or non-vulnerable. It
            focuses on memory and pointer-related risks such as buffer overflow,
            unsafe memory access, and NULL pointer issues.
          </p>

          <div className="home-buttons">
            <button className="home-primary-btn" onClick={goToAnalyze}>
              START ANALYSIS →
            </button>

            <button className="home-secondary-btn" onClick={goToAbout}>
              VIEW PROJECT INFO
            </button>
          </div>

          <div className="home-quick-stats">
            <div>
              <strong>C</strong>
              <span>Source Code</span>
            </div>

            <div>
              <strong>2</strong>
              <span>Output Classes</span>
            </div>

            <div>
              <strong>CWE</strong>
              <span>Risk Categories</span>
            </div>
          </div>
        </div>

        <div className="home-code-card">
          <div className="home-code-header">
            <div className="home-window-dots">
              <span></span>
              <span></span>
              <span></span>
            </div>

            <p>buffer_check.c</p>
          </div>

          <div className="home-code-body">
            <p>
              <span>1</span> char buffer[20];
            </p>

            <p>
              <span>2</span> char userInput[100];
            </p>

            <p className="home-danger-line">
              <span>3</span> strcpy(buffer, userInput);
              <b>⚠</b>
            </p>

            <p>
              <span>4</span> features = vectorize(code);
            </p>

            <p className="home-scan-line">
              <span>5</span> prediction = model.predict(features);
            </p>

            <p>
              <span>6</span> return result;
            </p>
          </div>

          <div className="home-code-footer">
            <div className="home-ml-status">⚙ MODEL ACTIVE</div>
            <div className="home-issue-status">Potential Buffer Risk</div>
          </div>
        </div>
      </section>

      {/* MODEL FOCUS SECTION */}
      <section className="home-analysis-section">
        <h2>What Our Model Analyzes</h2>

        <p className="home-section-text">
          The model analyzes C source-code snippets using code-based text
          features and machine learning classification.
        </p>

        <div className="home-feature-grid">
          <div className="home-feature-card">
            <div className="home-feature-icon">{"{}"}</div>
            <h3>C Code Classification</h3>
            <p>
              Classifies submitted C code as vulnerable or non-vulnerable based
              on learned vulnerability patterns.
            </p>
          </div>

          <div className="home-feature-card">
            <div className="home-feature-icon">⚠</div>
            <h3>Memory Risk Detection</h3>
            <p>
              Focuses on buffer usage, pointer operations, unsafe memory access,
              and NULL pointer risks.
            </p>
          </div>

          <div className="home-feature-card">
            <div className="home-feature-icon">▣</div>
            <h3>TF-IDF Based Features</h3>
            <p>
              Uses word-level and character-level patterns to help the model
              understand code tokens and syntax.
            </p>
          </div>
        </div>
      </section>

      {/* WORKFLOW SECTION */}
      <section className="home-workflow-section">
        <h2>How the Web App Uses the Model</h2>

        <p className="home-section-text">
          The frontend collects user code, the backend processes it, and the
          trained model returns a vulnerability prediction.
        </p>

        <div className="workflow-grid">
          <div className="workflow-card">
            <span>01</span>
            <h3>Enter C Code</h3>
            <p>
              Users paste a C code snippet into the Analyze page input form.
            </p>
          </div>

          <div className="workflow-card">
            <span>02</span>
            <h3>Process Input</h3>
            <p>
              The backend prepares the code and converts it into model-ready
              features.
            </p>
          </div>

          <div className="workflow-card">
            <span>03</span>
            <h3>Run Prediction</h3>
            <p>
              The trained model predicts whether the code is vulnerable or
              non-vulnerable.
            </p>
          </div>

          <div className="workflow-card">
            <span>04</span>
            <h3>Show Result</h3>
            <p>
              The result is displayed with prediction status, confidence, and
              visual summaries.
            </p>
          </div>
        </div>
      </section>

      {/* CTA SECTION */}
      <section className="home-cta-section">
        <h2>Test a C Code Snippet</h2>

        <p>
          Use the Analyze page to submit C code and view the vulnerability
          prediction generated by the trained model.
        </p>

        <button className="home-primary-btn" onClick={goToAnalyze}>
          START ANALYSIS →
        </button>
      </section>
    </main>
  );
}

export default Home;