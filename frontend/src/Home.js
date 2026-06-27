import React from "react";
import "./Home.css";

// Landing page that introduces the detector and routes users into analysis.
function Home({ goToAnalyze, goToAbout }) {
  return (
    <main className="home-page">
      {/* HERO SECTION */}
      <section className="home-hero">
        <div className="home-hero-left">
          <span className="home-badge">
            <span className="home-dot"></span>
            C/C++ VULNERABILITY MODEL READY
          </span>

          <h1>
            Detect Risky C/C++ Code <br />
            with Machine Learning
          </h1>

          <p>
            This web application uses trained Assignment 2 model families to
            predict whether a C/C++ source-code snippet is vulnerable or
            non-vulnerable. Users can compare classical machine-learning models
            and CodeBERT variations.
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
              <strong>C/C++</strong>
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
              <span>1</span> #include &lt;string.h&gt;
            </p>

            <p>
              <span>2</span> int main(void) {"{"}
            </p>

            <p>
              <span>3</span> char buffer[20];
            </p>

            <p>
              <span>4</span> char userInput[100];
            </p>

            <p>
              <span>5</span> strcpy(buffer, userInput);
            </p>

            <p>
              <span>6</span> return 0; {"}"}
            </p>
          </div>

          <div className="home-code-footer">
            <div className="home-ml-status">BINARY CLASSIFICATION</div>
            <div className="home-issue-status">Vulnerable</div>
          </div>
        </div>
      </section>

      {/* MODEL FOCUS SECTION */}
      <section className="home-analysis-section">
        <h2>What Our Models Analyze</h2>

        <p className="home-section-text">
          The system analyzes C/C++ source-code snippets using classical text
          features, optional security features, and CodeBERT representations.
        </p>

        <div className="home-feature-grid">
          <div className="home-feature-card">
            <div className="home-feature-icon">{"{}"}</div>
            <h3>C/C++ Code Classification</h3>
            <p>
              Classifies submitted C/C++ code as vulnerable or non-vulnerable based
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
            <h3>Classical Models + CodeBERT</h3>
            <p>
              Supports TF-IDF machine-learning pipelines and fine-tuned
              CodeBERT checkpoints for binary vulnerability classification.
            </p>
          </div>
        </div>
      </section>

      {/* WORKFLOW SECTION */}
      <section className="home-workflow-section">
        <h2>How the Web App Uses the Models</h2>

        <p className="home-section-text">
          The frontend collects user code, the backend processes it, and the
          selected trained model returns a vulnerability prediction.
        </p>

        <div className="workflow-grid">
          <div className="workflow-card">
            <span>01</span>
            <h3>Enter C/C++ Code</h3>
            <p>
              Users paste a C/C++ code snippet into the Analyze page input form.
            </p>
          </div>

          <div className="workflow-card">
            <span>02</span>
            <h3>Process Input</h3>
            <p>
              The backend prepares the code using the preprocessing required
              by the selected model family.
            </p>
          </div>

          <div className="workflow-card">
            <span>03</span>
            <h3>Run Prediction</h3>
            <p>
              The selected model predicts whether the code is vulnerable or
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
        <h2>Test a C/C++ Code Snippet</h2>

        <p>
          Use the Analyze page to submit C/C++ code and view the vulnerability
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
