import { useEffect, useRef, useState } from "react";
import "./Analysis.css";

const API_URL = process.env.REACT_APP_API_URL || "http://127.0.0.1:8000";
const MAX_CODE_LENGTH = 20000;
const MODEL_FAMILIES = [
  ["random_forest", "Random Forest"],
  ["xgboost", "XGBoost"],
  ["logistic_regression", "Logistic Regression"],
  ["linear_svc", "LinearSVC"],
  ["ensemble", "Ensemble"],
  ["codebert", "CodeBERT"],
];
const MODEL_KEYS = {
  random_forest: ["randomforest", "features_randomforest"],
  xgboost: ["xgboost", "features_xgboost"],
  logistic_regression: ["logistic", "features_logistic"],
  linear_svc: ["linear_svc", "features_linear_svc"],
  ensemble: ["ensemble", "features_ensemble"],
  codebert: ["codebert", "codebert_cwe_balanced"],
};

const EXAMPLE_CODE = `#include <stdio.h>
#include <string.h>

int main(void) {
    char buffer[20];
    char user_input[100];

    fgets(user_input, sizeof(user_input), stdin);
    strcpy(buffer, user_input);
    printf("%s\\n", buffer);
    return 0;
}`;

const RISK_FIELDS = [
  ["Buffer memory", "buffer_memory_risk_level", "CWE-119"],
  ["Classic overflow", "classic_overflow_risk_level", "CWE-120"],
  ["Pointer subtraction", "pointer_subtraction_risk_level", "CWE-469"],
  ["NULL pointer", "null_pointer_risk_level", "CWE-476"],
  ["Integer and size", "integer_size_risk_level", "Supporting risk"],
  ["Other patterns", "other_cwe_risk_level", "CWE-OTHERS"],
];

const METRIC_FIELDS = [
  ["Unsafe functions", "count_unsafe_buffer_funcs"],
  ["Bounded functions", "count_bounded_buffer_funcs"],
  ["Pointer operations", "count_pointer_ops"],
  ["Array accesses", "count_array_accesses"],
  ["NULL checks", "count_null_checks"],
  ["Validation signals", "count_validation_signals"],
  ["Code lines", "snippet_length"],
  ["Tokens", "token_count"],
];

function riskName(value) {
  if (value >= 2) return "High";
  if (value === 1) return "Low";
  return "None";
}

function getErrorMessage(data, fallback) {
  if (typeof data?.detail === "string") return data.detail;
  if (Array.isArray(data?.detail)) return data.detail[0]?.msg || fallback;
  return fallback;
}

function Analysis() {
  const fileInput = useRef(null);
  const [code, setCode] = useState("");
  const [models, setModels] = useState([]);
  const [modelFamily, setModelFamily] = useState("random_forest");
  const [useVariation, setUseVariation] = useState(true);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [elapsedTime, setElapsedTime] = useState(null);

  useEffect(() => {
    fetch(`${API_URL}/models`)
      .then((response) => {
        if (!response.ok) throw new Error("Could not load the model list.");
        return response.json();
      })
      .then((data) => setModels(data))
      .catch((requestError) => setError(requestError.message));
  }, []);

  const selectedVariant = modelFamily === "codebert"
    ? useVariation ? "cwe_balanced" : "standard"
    : useVariation ? "handcrafted" : "standard";
  const selectedModel = models.find(
    (model) => model.family === modelFamily && model.variant === selectedVariant
  );
  const modelKey = selectedModel?.key || MODEL_KEYS[modelFamily][useVariation ? 1 : 0];

  function validateCode() {
    const cleaned = code.trim();
    if (cleaned.length < 20) return "Enter at least 20 characters of C/C++ code.";
    if (cleaned.length > MAX_CODE_LENGTH) {
      return `Code must be under ${MAX_CODE_LENGTH.toLocaleString()} characters.`;
    }
    if (!/[;{}]|#include|\b(int|void|char|float|double)\b/.test(cleaned)) {
      return "The input does not look like C/C++ source code.";
    }
    return "";
  }

  async function analyzeCode() {
    const validationError = validateCode();
    if (validationError) {
      setError(validationError);
      return;
    }

    setLoading(true);
    setError("");
    setElapsedTime(null);
    const startedAt = performance.now();

    try {
      const response = await fetch(`${API_URL}/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: code.trim(), model_key: modelKey }),
      });
      const data = await response.json();

      if (!response.ok) {
        throw new Error(getErrorMessage(data, "Prediction could not be completed."));
      }

      setResult(data);
      setHistory((current) => [data, ...current].slice(0, 3));
      setElapsedTime((performance.now() - startedAt) / 1000);
    } catch (requestError) {
      setError(
        requestError.message === "Failed to fetch"
          ? "Cannot connect to FastAPI. Start the backend and try again."
          : requestError.message
      );
    } finally {
      setLoading(false);
    }
  }

  function loadFile(event) {
    const file = event.target.files[0];
    if (!file) return;

    const extension = file.name.split(".").pop().toLowerCase();
    if (!["c", "cc", "cpp", "h", "hpp"].includes(extension)) {
      setError("Upload a C/C++ source file: .c, .cc, .cpp, .h, or .hpp.");
      return;
    }

    if (file.size > 100000) {
      setError("The uploaded file must be smaller than 100 KB.");
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      setCode(String(reader.result).slice(0, MAX_CODE_LENGTH));
      setResult(null);
      setError("");
      setElapsedTime(null);
    };
    reader.onerror = () => setError("The selected file could not be read.");
    reader.readAsText(file);
    event.target.value = "";
  }

  function clearCode() {
    setCode("");
    setResult(null);
    setError("");
    setElapsedTime(null);
  }

  function exportResult() {
    if (!result) return;
    const file = new Blob([JSON.stringify({ code, ...result }, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(file);
    const link = document.createElement("a");
    link.href = url;
    link.download = `vulnerability-analysis-${Date.now()}.json`;
    link.click();
    URL.revokeObjectURL(url);
  }

  const isVulnerable = result?.label === "VULNERABLE";

  return (
    <main className="analysis-page">
      <section className="analysis-intro">
        <div>
          <p>Machine Learning Analysis</p>
          <h1>Analyze C/C++ Source Code</h1>
          <span>
            Submit a code snippet to classify it and inspect the model's
            extracted risk indicators.
          </span>
        </div>
        <div className="analysis-api-status">
          <i />
          {models.length ? `${models.length} models available` : "Connecting to API"}
        </div>
      </section>

      <section className="analysis-workspace">
        <div className="analysis-toolbar">
          <div className="analysis-model-controls">
            <label>
              Model family
              <select
                onChange={(event) => {
                  setModelFamily(event.target.value);
                  setElapsedTime(null);
                }}
                value={modelFamily}
              >
                {MODEL_FAMILIES.map(([key, label]) => (
                  <option key={key} value={key}>{label}</option>
                ))}
              </select>
            </label>

            <label className="analysis-variation">
              <input
                checked={useVariation}
                onChange={(event) => {
                  setUseVariation(event.target.checked);
                  setElapsedTime(null);
                }}
                type="checkbox"
              />
              <span>
                <strong>
                  {modelFamily === "codebert"
                    ? "CWE-balanced training"
                    : "Include handcrafted features"}
                </strong>
                <small>
                  {modelFamily === "codebert"
                    ? "Use the checkpoint balanced across CWE groups."
                    : "Use the model trained with security feature columns."}
                </small>
              </span>
            </label>
          </div>

          <div className="analysis-toolbar-actions">
            <button type="button" onClick={() => fileInput.current?.click()}>
              Upload file
            </button>
            <button
              type="button"
              onClick={() => {
                setCode(EXAMPLE_CODE);
                setResult(null);
                setError("");
                setElapsedTime(null);
              }}
            >
              Load example
            </button>
            <button type="button" onClick={clearCode}>Clear</button>
          </div>
        </div>

        <input
          accept=".c,.cc,.cpp,.h,.hpp,text/plain"
          className="analysis-file-input"
          onChange={loadFile}
          ref={fileInput}
          type="file"
        />

        <label className="analysis-editor">
          <span>Source code</span>
          <textarea
            maxLength={MAX_CODE_LENGTH}
            onChange={(event) => {
              setCode(event.target.value);
              setError("");
              setElapsedTime(null);
            }}
            placeholder="Paste C/C++ source code here..."
            spellCheck="false"
            value={code}
          />
        </label>

        <div className="analysis-editor-footer">
          <span>{code.length.toLocaleString()} / {MAX_CODE_LENGTH.toLocaleString()} characters</span>
          <span>{code.split("\n").filter((line) => line.trim()).length} non-empty lines</span>
        </div>

        {error && <div className="analysis-error" role="alert">{error}</div>}

        <div className="analysis-submit-row">
          <div>
            <strong>{selectedModel?.name || "Random Forest with features"}</strong>
            <span>
              {selectedModel?.supports_probability === false
                ? "This model does not provide a confidence probability."
                : "Confidence is shown when supported by the selected model."}
            </span>
          </div>
          <div className="analysis-submit-action">
            {elapsedTime !== null && (
              <span>Completed in {elapsedTime.toFixed(2)} seconds</span>
            )}
            <button
              className="analysis-submit"
              disabled={loading}
              onClick={analyzeCode}
              type="button"
            >
              {loading ? "Analyzing..." : "Analyze code"}
            </button>
          </div>
        </div>
      </section>

      {!result && (
        <section className="analysis-empty">
          <strong>Results will appear here</strong>
          <span>
            The model returns a binary classification, confidence score, risk
            indicators, and code metrics.
          </span>
        </section>
      )}

      {result && (
        <section className="analysis-results" aria-live="polite">
          <div className="analysis-results-heading">
            <div>
              <p>Prediction Result</p>
              <h2>Analysis Summary</h2>
              <span className="analysis-confidence-note">
                Confidence is shown only when the selected model produces
                probability estimates. LinearSVC and hard-voting Ensemble
                models may display “Not available”.
              </span>
            </div>
            <button type="button" onClick={exportResult}>Export JSON</button>
          </div>

          <div className="analysis-summary-grid">
            <article className={`analysis-status ${isVulnerable ? "is-vulnerable" : "is-safe"}`}>
              <span>Classification</span>
              <strong>{isVulnerable ? "Vulnerable" : "Non-vulnerable"}</strong>
              <small>Binary model prediction</small>
            </article>
            <article>
              <span>Confidence</span>
              <strong>
                {result.confidence_percent == null
                  ? "Not available"
                  : `${result.confidence_percent.toFixed(2)}%`}
              </strong>
              <small>{result.model_name}</small>
            </article>
            <article>
              <span>Vulnerable probability</span>
              <strong>
                {result.vulnerable_probability == null
                  ? "Not available"
                  : `${(result.vulnerable_probability * 100).toFixed(2)}%`}
              </strong>
              <small>{new Date(result.created_at).toLocaleString()}</small>
            </article>
          </div>

          <div className="analysis-detail-grid">
            <article className="analysis-panel">
              <div className="analysis-panel-heading">
                <p>Feature Extraction</p>
                <h3>Risk Indicators</h3>
              </div>
              <div className="analysis-risk-list">
                {RISK_FIELDS.map(([label, field, cwe]) => {
                  const value = result.features[field];
                  return (
                    <div key={field}>
                      <span><strong>{label}</strong><small>{cwe}</small></span>
                      <b className={`risk-level risk-${value}`}>{riskName(value)}</b>
                    </div>
                  );
                })}
              </div>
            </article>

            <article className="analysis-panel">
              <div className="analysis-panel-heading">
                <p>Submitted Snippet</p>
                <h3>Code Metrics</h3>
              </div>
              <div className="analysis-metrics">
                {METRIC_FIELDS.map(([label, field]) => (
                  <div key={field}>
                    <span>{label}</span>
                    <strong>{result.features[field]}</strong>
                  </div>
                ))}
              </div>
            </article>
          </div>

          {history.length > 1 && (
            <article className="analysis-history">
              <div className="analysis-panel-heading">
                <p>Current Session</p>
                <h3>Recent Analyses</h3>
              </div>
              <div>
                {history.map((item, index) => (
                  <button
                    key={`${item.created_at}-${index}`}
                    onClick={() => setResult(item)}
                    type="button"
                  >
                    <span>{item.model_name}</span>
                    <strong className={item.label === "VULNERABLE" ? "history-danger" : "history-safe"}>
                      {item.label.replace("_", " ")}
                    </strong>
                    <small>
                      {item.confidence_percent == null
                        ? "No confidence"
                        : `${item.confidence_percent.toFixed(2)}% confidence`}
                    </small>
                  </button>
                ))}
              </div>
            </article>
          )}

          <p className="analysis-disclaimer">
            This result is a machine-learning classification, not a complete
            security audit. Review important code manually and with established
            static-analysis tools.
          </p>
        </section>
      )}
    </main>
  );
}

export default Analysis;
