import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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

const RISK_CHART_COLORS = ["#2dd4a8", "#f5c96b", "#ff6b7a"];
const RISK_AXIS_LABELS = ["None", "Low", "High"];

const FALLBACK_MODEL_OPTIONS = Object.values(MODEL_KEYS).flat();
const FALLBACK_COMPARISON_OPTIONS = FALLBACK_MODEL_OPTIONS.filter(
  (key) => !key.startsWith("codebert")
);

function riskName(value) {
  if (value >= 2) return "High";
  if (value === 1) return "Low";
  return "None";
}

function getErrorMessage(data, fallback) {
  // FastAPI may return errors as strings or validation arrays; make one message.
  if (typeof data?.detail === "string") return data.detail;
  if (Array.isArray(data?.detail)) return data.detail[0]?.msg || fallback;
  return fallback;
}

function explainRisk(features) {
  // Convert extracted feature values into short explanations for the user.
  if (!features) return [];

  const notes = [];
  if (features.count_unsafe_buffer_funcs > 0) {
    notes.push({
      level: "High",
      title: "Unsafe buffer function detected",
      detail: `${features.count_unsafe_buffer_funcs} unsafe call(s), such as strcpy-style memory copying, were found.`,
    });
  }
  if (features.buffer_memory_risk_level > 0) {
    notes.push({
      level: riskName(features.buffer_memory_risk_level),
      title: "Buffer or memory pattern matched",
      detail: "The snippet contains syntax patterns related to buffer handling or memory operations.",
    });
  }
  if (features.null_pointer_risk_level > 0) {
    notes.push({
      level: riskName(features.null_pointer_risk_level),
      title: "NULL pointer risk signal",
      detail: "The extracted features found pointer usage that may require stronger NULL validation.",
    });
  }
  if (features.count_validation_signals > 0) {
    notes.push({
      level: "Positive",
      title: "Validation signal present",
      detail: `${features.count_validation_signals} validation-related signal(s) may reduce risk.`,
    });
  }

  if (notes.length === 0) {
    notes.push({
      level: "Low",
      title: "No major handcrafted risk signal",
      detail: "The feature extractor did not find strong buffer, pointer, or validation warning patterns.",
    });
  }
  return notes.slice(0, 4);
}

function clampNumber(value, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return min;
  return Math.min(Math.max(number, min), max);
}

function featureNumber(features, field) {
  const value = Number(features?.[field]);
  return Number.isFinite(value) ? value : 0;
}

function formatPercent(value) {
  return (value * 100).toFixed(1) + "%";
}

function buildAnalysisChartData(result) {
  // Prepare prediction probability, risk levels, and code metrics for charts.
  const features = result?.features || {};
  const probability = Number(result?.vulnerable_probability);
  const confidence = Number(result?.confidence_percent);
  const vulnerableScore = Number.isFinite(probability)
    ? clampNumber(probability, 0, 1)
    : Number.isFinite(confidence)
    ? result?.label === "VULNERABLE"
      ? clampNumber(confidence / 100, 0, 1)
      : 1 - clampNumber(confidence / 100, 0, 1)
    : null;

  return {
    probability: vulnerableScore == null
      ? []
      : [
          { label: "Vulnerable", value: vulnerableScore, color: "#ff6b7a" },
          { label: "Non-vulnerable", value: 1 - vulnerableScore, color: "#2dd4a8" },
        ],
    riskScale: RISK_AXIS_LABELS.map((label, index) => ({
      color: RISK_CHART_COLORS[index],
      label,
    })),
    metrics: METRIC_FIELDS.map(([label, field]) => ({
      field,
      label,
      value: Math.max(0, featureNumber(features, field)),
    })),
    risks: RISK_FIELDS.map(([label, field, cwe]) => {
      const value = clampNumber(featureNumber(features, field), 0, 2);
      return {
        cwe,
        label,
        level: riskName(value),
        value,
        color: RISK_CHART_COLORS[value] || RISK_CHART_COLORS[0],
      };
    }),
  };
}

function useD3Chart(draw, data) {
  // Shared D3 hook: render the chart and redraw when its container changes size.
  const chartRef = useRef(null);

  useEffect(() => {
    const container = chartRef.current;
    if (!container) return undefined;

    let cancelled = false;
    let observer;
    let removeResizeListener;

    import("d3").then((d3) => {
      if (cancelled) return;
      const render = () => draw(d3, container, data);
      render();

      if (typeof ResizeObserver !== "undefined") {
        observer = new ResizeObserver(render);
        observer.observe(container);
      } else {
        window.addEventListener("resize", render);
        removeResizeListener = () => window.removeEventListener("resize", render);
      }
    });

    return () => {
      cancelled = true;
      if (observer) observer.disconnect();
      if (removeResizeListener) removeResizeListener();
    };
  }, [draw, data]);

  return chartRef;
}

function drawProbabilityDonut(d3, container, rows) {
  // Draw vulnerable vs non-vulnerable probability when the model provides it.
  const width = Math.max(container.clientWidth || 0, 220);
  const size = Math.min(width, 260);
  const radius = size / 2;
  const svg = d3.select(container).selectAll("svg").data([null]).join("svg")
    .attr("aria-label", "Vulnerability probability donut chart")
    .attr("role", "img")
    .attr("viewBox", "0 0 " + size + " " + size);
  svg.selectAll("*").remove();

  const group = svg.append("g")
    .attr("transform", "translate(" + radius + "," + radius + ")");

  if (!rows.length) {
    group.append("circle")
      .attr("class", "analysis-d3-empty-ring")
      .attr("r", radius * 0.74);
    group.append("text")
      .attr("class", "analysis-d3-center-label")
      .attr("text-anchor", "middle")
      .attr("dominant-baseline", "middle")
      .text("N/A");
    return;
  }

  const arc = d3.arc()
    .innerRadius(radius * 0.58)
    .outerRadius(radius * 0.9)
    .cornerRadius(4);
  const pie = d3.pie().sort(null).value((item) => item.value);

  group.selectAll("path")
    .data(pie(rows))
    .join("path")
    .attr("d", arc)
    .attr("fill", (item) => item.data.color)
    .attr("stroke", "#111c30")
    .attr("stroke-width", 4)
    .append("title")
    .text((item) => item.data.label + ": " + formatPercent(item.data.value));

  group.append("text")
    .attr("class", "analysis-d3-center-label")
    .attr("text-anchor", "middle")
    .attr("dominant-baseline", "middle")
    .attr("y", -6)
    .text(formatPercent(rows[0].value));
  group.append("text")
    .attr("class", "analysis-d3-center-subtitle")
    .attr("text-anchor", "middle")
    .attr("dominant-baseline", "middle")
    .attr("y", 17)
    .text("Vulnerable");
}

function drawRiskRadar(d3, container, rows) {
  // Draw the extracted risk indicators on a 0-2 radar scale.
  const width = Math.max(container.clientWidth || 0, 300);
  const size = Math.min(width, 300);
  const center = size / 2;
  const radius = size * 0.4;
  const angle = (index) => (Math.PI * 2 * index) / rows.length - Math.PI / 2;
  const pointFor = (item, index, scale = item.value / 2) => {
    const distance = radius * clampNumber(scale, 0, 1);
    return [
      center + Math.cos(angle(index)) * distance,
      center + Math.sin(angle(index)) * distance,
    ];
  };
  const svg = d3.select(container).selectAll("svg").data([null]).join("svg")
    .attr("aria-label", "Risk indicator radar chart")
    .attr("role", "img")
    .attr("viewBox", "0 0 " + size + " " + size);
  svg.selectAll("*").remove();

  const ringLine = d3.line().curve(d3.curveLinearClosed);
  svg.append("g").selectAll("path")
    .data([1 / 3, 2 / 3, 1])
    .join("path")
    .attr("class", "analysis-d3-radar-ring")
    .attr("d", (scale) => ringLine(rows.map((item, index) => pointFor(item, index, scale))));

  svg.append("g").selectAll("line")
    .data(rows)
    .join("line")
    .attr("class", "analysis-d3-radar-spoke")
    .attr("x1", center)
    .attr("y1", center)
    .attr("x2", (item, index) => pointFor(item, index, 1)[0])
    .attr("y2", (item, index) => pointFor(item, index, 1)[1]);

  const plottedPoints = rows.map((item, index) => ({
    ...item,
    point: pointFor(item, index),
  }));
  const radarLine = d3.line()
    .x((item) => item.point[0])
    .y((item) => item.point[1])
    .curve(d3.curveLinearClosed);
  svg.append("path")
    .datum(plottedPoints)
    .attr("class", "analysis-d3-radar-area")
    .attr("d", radarLine);

  svg.append("g").selectAll("circle")
    .data(plottedPoints)
    .join("circle")
    .attr("class", "analysis-d3-radar-point")
    .attr("cx", (item) => item.point[0])
    .attr("cy", (item) => item.point[1])
    .attr("fill", (item) => item.color)
    .attr("r", 5)
    .append("title")
    .text((item) => item.label + ": " + item.level + " risk (" + item.cwe + ")");

  svg.append("g").selectAll("text")
    .data(rows)
    .join("text")
    .attr("class", "analysis-d3-radar-label")
    .attr("text-anchor", "middle")
    .attr("dominant-baseline", "middle")
    .attr("x", (item, index) => pointFor(item, index, 1.16)[0])
    .attr("y", (item, index) => pointFor(item, index, 1.16)[1])
    .text((item) => item.label.split(" ").map((word) => word[0]).join(""));
}

function ProbabilityDonutChart({ rows }) {
  const chartRef = useD3Chart(drawProbabilityDonut, rows);
  return <div className="analysis-d3-chart analysis-d3-donut" ref={chartRef} />;
}

function RiskRadarChart({ rows }) {
  const chartRef = useD3Chart(drawRiskRadar, rows);
  return <div className="analysis-d3-chart analysis-d3-radar" ref={chartRef} />;
}


function drawMetricsChart(d3, container, rows) {
  // Draw extracted code metrics as a compact bar chart.
  const width = Math.max(container.clientWidth || 0, 260);
  const height = 250;
  const margin = { top: 22, right: 12, bottom: 34, left: 12 };
  const chartBottom = height - margin.bottom;
  const maximum = d3.max(rows, (item) => item.value) || 1;
  const x = d3.scaleBand()
    .domain(rows.map((item) => item.label))
    .range([margin.left, width - margin.right])
    .padding(0.24);
  const y = d3.scaleLinear().domain([0, maximum]).nice().range([chartBottom, margin.top]);
  const svg = d3.select(container).selectAll("svg").data([null]).join("svg")
    .attr("aria-label", "Code metrics histogram chart")
    .attr("role", "img")
    .attr("viewBox", "0 0 " + width + " " + height);
  svg.selectAll("*").remove();

  svg.append("g").selectAll("line")
    .data(y.ticks(4))
    .join("line")
    .attr("class", "analysis-d3-metric-guide")
    .attr("x1", margin.left)
    .attr("x2", width - margin.right)
    .attr("y1", (value) => y(value))
    .attr("y2", (value) => y(value));

  svg.append("line")
    .attr("class", "analysis-d3-histogram-baseline")
    .attr("x1", margin.left)
    .attr("x2", width - margin.right)
    .attr("y1", chartBottom)
    .attr("y2", chartBottom);

  svg.append("g").selectAll("rect")
    .data(rows)
    .join("rect")
    .attr("class", "analysis-d3-metric-bar")
    .attr("x", (item) => x(item.label))
    .attr("y", (item) => y(item.value))
    .attr("width", x.bandwidth())
    .attr("height", (item) => chartBottom - y(item.value))
    .attr("rx", 4)
    .append("title")
    .text((item) => item.label + ": " + item.value.toLocaleString());

  svg.append("g").selectAll("text")
    .data(rows)
    .join("text")
    .attr("class", "analysis-d3-metric-value")
    .attr("text-anchor", "middle")
    .attr("x", (item) => x(item.label) + x.bandwidth() / 2)
    .attr("y", (item) => Math.max(12, y(item.value) - 5))
    .text((item) => item.value.toLocaleString());

  svg.append("g").selectAll("text")
    .data(rows)
    .join("text")
    .attr("class", "analysis-d3-metric-code")
    .attr("text-anchor", "middle")
    .attr("x", (item) => x(item.label) + x.bandwidth() / 2)
    .attr("y", height - 10)
    .text((item) => item.label.split(" ").map((word) => word[0]).join(""));
}

function MetricsChart({ rows }) {
  const chartRef = useD3Chart(drawMetricsChart, rows);
  return <div className="analysis-d3-chart analysis-d3-metrics-chart" ref={chartRef} />;
}

function AnalysisResultChart({ result }) {
  // Builds the complete visual result panel from one prediction response.
  const chartData = useMemo(() => buildAnalysisChartData(result), [result]);
  const probabilityLegend = chartData.probability.length
    ? chartData.probability
    : [{ color: "#354461", label: "Probability unavailable", value: null }];

  return (
    <article className="analysis-panel analysis-d3-panel">
      <div className="analysis-d3-grid">
        <div className="analysis-d3-card">
          <div className="analysis-d3-card-heading">
            <span>Probability</span>
          </div>
          <ProbabilityDonutChart rows={chartData.probability} />
          <div className="analysis-d3-legend">
            {probabilityLegend.map((item) => (
              <div key={item.label}>
                <i style={{ background: item.color }} />
                <span>{item.label}</span>
                <strong>{item.value == null ? "N/A" : formatPercent(item.value)}</strong>
              </div>
            ))}
          </div>
        </div>

        <div className="analysis-d3-card">
          <div className="analysis-d3-card-heading">
            <span>Risk indicators</span>
            <div className="analysis-d3-scale-legend">
              {chartData.riskScale.map((item) => (
                <b key={item.label}>
                  <i style={{ background: item.color }} />
                  {item.label}
                </b>
              ))}
            </div>
          </div>
          <RiskRadarChart rows={chartData.risks} />
          <div className="analysis-d3-risk-legend">
            {chartData.risks.map((item) => (
              <div key={item.label}>
                <i style={{ background: item.color }} />
                <span>{item.label}</span>
                <strong>{item.level}</strong>
              </div>
            ))}
          </div>
        </div>

        <div className="analysis-d3-card">
          <div className="analysis-d3-card-heading">
            <span>Code metrics histogram</span>
          </div>
          <MetricsChart rows={chartData.metrics} />
          <div className="analysis-d3-risk-legend analysis-d3-metric-legend">
            {chartData.metrics.map((item) => (
              <div key={item.field}>
                <i />
                <span>{item.label}</span>
                <strong>{item.value.toLocaleString()}</strong>
              </div>
            ))}
          </div>
        </div>
      </div>
    </article>
  );
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
  const [comparisonLoading, setComparisonLoading] = useState(false);
  const [comparisonResults, setComparisonResults] = useState([]);
  const [comparisonProgress, setComparisonProgress] = useState("");
  const [elapsedTime, setElapsedTime] = useState(null);
  const [apiStatus, setApiStatus] = useState("connecting");

  const loadModels = useCallback(() => {
    // Ask the backend for model metadata used by the dropdown and labels.
    setApiStatus("connecting");
    setError("");
    fetch(`${API_URL}/models`)
      .then((response) => {
        if (!response.ok) throw new Error("Could not load the model list.");
        return response.json();
      })
      .then((data) => {
        setModels(data);
        setApiStatus("connected");
      })
      .catch((requestError) => {
        setModels([]);
        setApiStatus("unavailable");
        setError(requestError.message);
      });
  }, []);

  useEffect(() => {
    loadModels();
  }, [loadModels]);

  const selectedVariant = modelFamily === "codebert"
    ? useVariation ? "cwe_balanced" : "standard"
    : useVariation ? "handcrafted" : "standard";
  const selectedModel = models.find(
    (model) => model.family === modelFamily && model.variant === selectedVariant
  );
  const modelKey = selectedModel?.key || MODEL_KEYS[modelFamily][useVariation ? 1 : 0];

  function validateCode() {
    // Stop invalid input before making a backend prediction request.
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
    // Main prediction flow: send code + model key to POST /predict.
    const validationError = validateCode();
    if (validationError) {
      setError(validationError);
      return;
    }

    setLoading(true);
    setError("");
    setElapsedTime(null);
    const startedAt = performance.now();
    const controller = new AbortController();
    const timeout = window.setTimeout(
      () => controller.abort(),
      modelFamily === "codebert" ? 120000 : 30000
    );

    try {
      const response = await fetch(`${API_URL}/predict`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: code.trim(), model_key: modelKey }),
        signal: controller.signal,
      });
      const data = await response.json();

      if (!response.ok) {
        throw new Error(getErrorMessage(data, "Prediction could not be completed."));
      }

      const completedAnalysis = {
        ...data,
        submitted_code: code.trim(),
      };
      setResult(completedAnalysis);
      setComparisonResults([]);
      setComparisonProgress("");
      setHistory((current) => [completedAnalysis, ...current].slice(0, 3));
      setElapsedTime((performance.now() - startedAt) / 1000);
    } catch (requestError) {
      setError(
        requestError.name === "AbortError"
          ? "The analysis timed out. Check the backend and try again."
          : requestError.message === "Failed to fetch"
          ? "Cannot connect to FastAPI. Start the backend and try again."
          : requestError.message
      );
    } finally {
      window.clearTimeout(timeout);
      setLoading(false);
    }
  }

  async function compareModels() {
    // Compare the same snippet across classical models without loading CodeBERT.
    const validationError = validateCode();
    if (validationError) {
      setError(validationError);
      return;
    }

    const availableKeys = models.length
      ? models
          .filter((model) => model.model_type !== "codebert")
          .map((model) => model.key)
      : FALLBACK_COMPARISON_OPTIONS;

    setComparisonLoading(true);
    setComparisonResults([]);
    setComparisonProgress(`0 / ${availableKeys.length} models completed`);
    setError("");

    const completed = [];
    for (let index = 0; index < availableKeys.length; index += 1) {
      const key = availableKeys[index];
      try {
        const response = await fetch(`${API_URL}/predict`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ code: code.trim(), model_key: key }),
        });
        const data = await response.json();
        if (!response.ok) {
          throw new Error(getErrorMessage(data, "Prediction failed."));
        }
        completed.push({ ...data, error: "" });
      } catch (requestError) {
        completed.push({
          model_key: key,
          model_name: models.find((model) => model.key === key)?.name || key,
          label: "FAILED",
          confidence_percent: null,
          vulnerable_probability: null,
          error: requestError.message,
        });
      }
      setComparisonResults([...completed]);
      setComparisonProgress(`${index + 1} / ${availableKeys.length} models completed`);
    }

    setComparisonLoading(false);
  }

  function loadFile(event) {
    // Load a local source file into the editor after type and size checks.
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
      setComparisonResults([]);
      setComparisonProgress("");
      setError("");
      setElapsedTime(null);
    };
    reader.onerror = () => setError("The selected file could not be read.");
    reader.readAsText(file);
    event.target.value = "";
  }

  function clearCode() {
    // Reset editor content and all prediction/comparison output.
    setCode("");
    setResult(null);
    setComparisonResults([]);
    setComparisonProgress("");
    setError("");
    setElapsedTime(null);
  }

  function exportResult() {
    // Save the latest prediction response as a local JSON file.
    if (!result) return;
    const { submitted_code: submittedCode, ...prediction } = result;
    const file = new Blob([JSON.stringify({
      code: submittedCode,
      ...prediction,
    }, null, 2)], {
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
            Submit C/C++ code snippet to classify it and inspect the model's
            extracted risk indicators.
          </span>
        </div>
        <div className={`analysis-api-status is-${apiStatus}`}>
          <i />
          <span>
            {apiStatus === "connecting" && "Connecting to API"}
            {apiStatus === "connected" && `${models.length} models available`}
            {apiStatus === "unavailable" && "Model API unavailable"}
          </span>
          {apiStatus === "unavailable" && (
            <button onClick={loadModels} type="button">Retry</button>
          )}
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
                  setResult(null);
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
                  setResult(null);
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
                setComparisonResults([]);
                setComparisonProgress("");
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
              setResult(null);
              setComparisonResults([]);
              setComparisonProgress("");
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
              {loading
                ? modelFamily === "codebert"
                  ? "Loading CodeBERT and analyzing..."
                  : "Analyzing..."
                : "Analyze code"}
            </button>
            <button
              className="analysis-compare"
              disabled={loading || comparisonLoading}
              onClick={compareModels}
              type="button"
            >
              {comparisonLoading ? "Comparing models..." : "Compare classical models"}
            </button>
            {comparisonProgress && (
              <small className="analysis-comparison-progress">
                {comparisonProgress}
              </small>
            )}
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
                models may display "Not available".
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

          <article className="analysis-panel analysis-explanation-panel">
            <div className="analysis-panel-heading">
              <p>Model Explainability</p>
              <h3>Why This Result?</h3>
            </div>
            <div className="analysis-explanation-list">
              {explainRisk(result.features).map((item) => (
                <div key={item.title}>
                  <b className={`explanation-level explanation-${item.level.toLowerCase()}`}>
                    {item.level}
                  </b>
                  <span>
                    <strong>{item.title}</strong>
                    <small>{item.detail}</small>
                  </span>
                </div>
              ))}
            </div>
          </article>

          <AnalysisResultChart result={result} />

          {comparisonResults.length > 0 && (
            <article className="analysis-comparison">
              <div className="analysis-panel-heading">
                <p>Model Comparison</p>
                <h3>Same Snippet Across Classical Models</h3>
                <span className="analysis-confidence-note">
                  CodeBERT is excluded from this batch comparison because it is
                  much larger and can be run from the model selector above.
                </span>
              </div>
              <div className="analysis-comparison-grid">
                {comparisonResults.map((item) => (
                  <div
                    className={
                      item.label === "VULNERABLE"
                        ? "is-vulnerable"
                        : item.label === "NON_VULNERABLE"
                        ? "is-safe"
                        : "is-failed"
                    }
                    key={item.model_key}
                  >
                    <span>{item.model_name}</span>
                    <strong>{item.label.replace("_", " ")}</strong>
                    <small>
                      {item.error
                        ? item.error
                        : item.confidence_percent == null
                        ? "Confidence not available"
                        : `${item.confidence_percent.toFixed(2)}% confidence`}
                    </small>
                  </div>
                ))}
              </div>
            </article>
          )}

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
