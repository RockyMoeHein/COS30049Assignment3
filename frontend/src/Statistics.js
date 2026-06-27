import { useEffect, useMemo, useRef, useState } from 'react';
import * as d3 from 'd3';
import './Statistics.css';

const API_BASE_URL = process.env.REACT_APP_API_URL || 'http://127.0.0.1:8000';
const ACTUAL_COLOR = '#2997ff';
const PROCESSED_COLOR = '#8b7cf6';
const formatNumber = (value = 0) => new Intl.NumberFormat('en-US').format(value);
const MODEL_METRICS = [
  { key: 'accuracy', label: 'Accuracy' },
  { key: 'vulnerable_precision', label: 'Vulnerable Precision' },
  { key: 'vulnerable_recall', label: 'Vulnerable Recall' },
  { key: 'vulnerable_f1', label: 'Vulnerable F1' },
  { key: 'macro_f1', label: 'Macro F1' },
];

function useChart(draw, redrawKey) {
  // Shared D3 rendering hook that redraws charts when data or size changes.
  const containerRef = useRef(null);
  const drawRef = useRef(draw);
  drawRef.current = draw;

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return undefined;

    const render = () => drawRef.current(container);
    render();

    const observer = new ResizeObserver(render);
    observer.observe(container);
    return () => observer.disconnect();
  }, [redrawKey]);

  return containerRef;
}

function showTooltip(tooltip, event, item, unit) {
  // Position and populate the small floating value tooltip used by all charts.
  tooltip
    .classed('is-visible', true)
    .style('left', `${event.offsetX + 12}px`)
    .style('top', `${event.offsetY - 10}px`)
    .html(
      `<strong>${item.label}</strong><span>${formatNumber(
        item.value
      )} ${unit}</span>`
    );
}

function makeInteractive(selection, getLabel, onActivate) {
  // Adds mouse and keyboard selection behaviour to D3 chart marks.
  selection
    .attr('aria-label', getLabel)
    .attr('role', 'button')
    .attr('tabindex', 0)
    .on('click', (_, item) => onActivate(item))
    .on('keydown', (event, item) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault();
        onActivate(item);
      }
    });
}

function ChartContainer({ chartRef, className, label }) {
  // Standard wrapper that gives every D3 chart a tooltip and accessible label.
  return (
    <div
      aria-label={label}
      className={`statistics-chart ${className}`}
      ref={chartRef}
      role="group"
    >
      <div className="statistics-tooltip" />
    </div>
  );
}

function DonutChart({ title, series, data, selectedItem, onSelect }) {
  // Compares vulnerable vs non-vulnerable label counts for one dataset split.
  const vulnerable = data?.VULNERABLE || 0;
  const nonVulnerable = data?.NON_VULNERABLE || 0;
  const total = vulnerable + nonVulnerable;
  const chartRef = useChart(
    (container) => {
      const size = Math.min(container.clientWidth, 230);
      const radius = size / 2;
      const values = [
        { label: 'Vulnerable', value: vulnerable, color: '#ff6b7a' },
        { label: 'Non-vulnerable', value: nonVulnerable, color: '#2dd4a8' },
      ];
      const svg = d3.select(container).selectAll('svg').data([null]).join('svg')
        .attr('aria-label', `${title} vulnerability label distribution`)
        .attr('viewBox', `0 0 ${size} ${size}`).attr('role', 'img');
      svg.selectAll('*').remove();

      const group = svg.append('g')
        .attr('transform', `translate(${radius},${radius})`);
      const arc = d3.arc()
        .innerRadius(radius * 0.62)
        .outerRadius(radius * 0.92)
        .cornerRadius(5);
      const pie = d3.pie().sort(null).value((item) => item.value);
      const tooltip = d3.select(container).select('.statistics-tooltip');

      const slices = group.selectAll('path').data(pie(values)).join('path')
        .attr('d', arc)
        .attr('fill', (item) => item.data.color)
        .attr('stroke', '#111a2e')
        .attr('stroke-width', (item) =>
          selectedItem?.series === series &&
          selectedItem?.label === item.data.label ? 6 : 3
        )
        .attr('opacity', (item) =>
          selectedItem?.series === series &&
          selectedItem?.label !== item.data.label ? 0.35 : 1
        )
        .style('cursor', 'pointer')
        .on('pointermove', (event, item) =>
          showTooltip(tooltip, event, item.data, 'samples')
        )
        .on('pointerleave', () => tooltip.classed('is-visible', false));

      makeInteractive(
        slices,
        (item) => `${title}, ${item.data.label}, ${formatNumber(item.data.value)} samples`,
        (item) => onSelect({
            chart: 'Vulnerability labels',
            series,
            label: item.data.label,
            value: item.data.value,
            unit: 'samples',
            total,
          })
      );

      group.append('text').attr('class', 'statistics-donut-value')
        .attr('text-anchor', 'middle').attr('y', -2)
        .text(`${total ? ((vulnerable / total) * 100).toFixed(1) : 0}%`);
      group.append('text').attr('class', 'statistics-donut-label')
        .attr('text-anchor', 'middle').attr('y', 20)
        .text('vulnerable');
    },
    JSON.stringify({ data, selectedItem, series })
  );

  return (
    <div className="statistics-comparison-item">
      <h3>{title}</h3>
      <ChartContainer
        chartRef={chartRef}
        className="statistics-donut-chart"
        label={`${title} vulnerability label chart`}
      />
      <div className="statistics-class-counts">
        <span><i className="statistics-count-vulnerable" />Vulnerable <strong>{formatNumber(vulnerable)}</strong></span>
        <span><i className="statistics-count-safe" />Non-vulnerable <strong>{formatNumber(nonVulnerable)}</strong></span>
      </div>
    </div>
  );
}

function comparisonRows(actualData, processedData) {
  // Convert two dictionaries into rows that can compare actual vs processed values.
  const labels = Array.from(
    new Set([
      ...Object.keys(actualData || {}),
      ...Object.keys(processedData || {}),
    ])
  );

  return labels.map((label) => ({
    label: label.replaceAll('_', ' '),
    actual: actualData?.[label] || 0,
    processed: processedData?.[label] || 0,
  }));
}

function GroupedColumnChart({
  actualData,
  processedData,
  chartName,
  unit,
  selectedItem,
  onSelect,
}) {
  // Shows actual and model-processed counts side-by-side for each category.
  const rows = useMemo(
    () => comparisonRows(actualData, processedData),
    [actualData, processedData]
  );
  const totals = {
    actual: d3.sum(rows, (item) => item.actual),
    processed: d3.sum(rows, (item) => item.processed),
  };
  const chartRef = useChart(
    (container) => {
      const width = Math.max(container.clientWidth, 300);
      const height = 270;
      const margin = { top: 18, right: 16, bottom: 62, left: 58 };
      const x = d3.scaleBand()
        .domain(rows.map((item) => item.label))
        .range([margin.left, width - margin.right])
        .padding(0.2);
      const seriesScale = d3.scaleBand()
        .domain(['actual', 'processed'])
        .range([0, x.bandwidth()])
        .padding(0.08);
      const maximum = d3.max(
        rows,
        (item) => Math.max(item.actual, item.processed)
      ) || 1;
      const y = d3.scaleLinear().domain([0, maximum]).nice()
        .range([height - margin.bottom, margin.top]);
      const svg = d3.select(container).selectAll('svg').data([null]).join('svg')
        .attr('aria-label', `${chartName} grouped column chart`)
        .attr('viewBox', `0 0 ${width} ${height}`).attr('role', 'img');
      svg.selectAll('*').remove();
      const tooltip = d3.select(container).select('.statistics-tooltip');

      svg.append('g').attr('class', 'statistics-grid')
        .attr('transform', `translate(${margin.left},0)`)
        .call(
          d3.axisLeft(y).ticks(4)
            .tickSize(-(width - margin.left - margin.right))
            .tickFormat('')
        );
      svg.append('g').attr('class', 'statistics-axis')
        .attr('transform', `translate(0,${height - margin.bottom})`)
        .call(d3.axisBottom(x).tickSize(0))
        .selectAll('text').attr('transform', 'rotate(-16)')
        .attr('text-anchor', 'end');
      svg.append('g').attr('class', 'statistics-axis')
        .attr('transform', `translate(${margin.left},0)`)
        .call(d3.axisLeft(y).ticks(4).tickFormat(d3.format('~s')));

      const marks = rows.flatMap((item) => [
        { label: item.label, value: item.actual, series: 'actual' },
        { label: item.label, value: item.processed, series: 'processed' },
      ]);

      const bars = svg.append('g').selectAll('rect').data(marks).join('rect')
        .attr('x', (item) => x(item.label) + seriesScale(item.series))
        .attr('y', (item) => y(item.value))
        .attr('width', seriesScale.bandwidth())
        .attr('height', (item) => height - margin.bottom - y(item.value))
        .attr('rx', 4)
        .attr('fill', (item) =>
          item.series === 'actual' ? ACTUAL_COLOR : PROCESSED_COLOR
        )
        .attr('opacity', (item) =>
          selectedItem?.chart === chartName &&
          (selectedItem.series !== item.series ||
            selectedItem.label !== item.label) ? 0.25 : 1
        )
        .style('cursor', 'pointer')
        .on('pointermove', (event, item) =>
          showTooltip(tooltip, event, item, unit)
        )
        .on('pointerleave', () => tooltip.classed('is-visible', false));

      makeInteractive(
        bars,
        (item) => `${item.series}, ${item.label}, ${formatNumber(item.value)} ${unit}`,
        (item) => onSelect({
            chart: chartName,
            series: item.series,
            label: item.label,
            value: item.value,
            unit,
            total: totals[item.series],
          })
      );
    },
    JSON.stringify({ rows, selectedItem, chartName })
  );

  return (
    <ChartContainer
      chartRef={chartRef}
      className="statistics-column-chart"
      label={`${chartName} grouped column chart`}
    />
  );
}

function LollipopChart({
  actualData,
  processedData,
  selectedItem,
  onSelect,
}) {
  // Shows CWE coverage as paired actual/processed lollipop marks.
  const rows = useMemo(
    () => comparisonRows(actualData, processedData),
    [actualData, processedData]
  );
  const totals = {
    actual: d3.sum(rows, (item) => item.actual),
    processed: d3.sum(rows, (item) => item.processed),
  };
  const chartRef = useChart(
    (container) => {
      const width = Math.max(container.clientWidth, 300);
      const height = Math.max(rows.length * 56 + 42, 150);
      const margin = {
        top: 36,
        right: width < 520 ? 62 : 86,
        bottom: 8,
        left: width < 520 ? 94 : 126,
      };
      const maximum = d3.max(
        rows,
        (item) => Math.max(item.actual, item.processed)
      ) || 1;
      const x = d3.scaleLinear().domain([0, maximum])
        .range([margin.left, width - margin.right]);
      const y = d3.scaleBand().domain(rows.map((item) => item.label))
        .range([margin.top, height - margin.bottom]).padding(0.35);
      const svg = d3.select(container).selectAll('svg').data([null]).join('svg')
        .attr('aria-label', 'Covered CWE groups lollipop chart')
        .attr('viewBox', `0 0 ${width} ${height}`).attr('role', 'img');
      svg.selectAll('*').remove();
      const tooltip = d3.select(container).select('.statistics-tooltip');

      const localLegend = [
        { label: 'Actual', color: ACTUAL_COLOR, x: margin.left },
        { label: 'Processed', color: PROCESSED_COLOR, x: margin.left + 88 },
      ];
      const legend = svg.append('g').selectAll('g')
        .data(localLegend).join('g')
        .attr('transform', (item) => `translate(${item.x},12)`);
      legend.append('circle').attr('r', 4).attr('fill', (item) => item.color);
      legend.append('text').attr('class', 'statistics-chart-key')
        .attr('x', 9).attr('y', 4).text((item) => item.label);

      svg.append('g').selectAll('text').data(rows).join('text')
        .attr('class', 'statistics-axis-label')
        .attr('x', margin.left - 12)
        .attr('y', (item) => y(item.label) + y.bandwidth() / 2)
        .attr('text-anchor', 'end').attr('dominant-baseline', 'middle')
        .text((item) => item.label);

      const marks = rows.flatMap((item) => [
        { label: item.label, value: item.actual, series: 'actual', offset: -6 },
        { label: item.label, value: item.processed, series: 'processed', offset: 6 },
      ]);

      svg.append('g').selectAll('line').data(marks).join('line')
        .attr('x1', margin.left).attr('x2', (item) => x(item.value))
        .attr('y1', (item) => y(item.label) + y.bandwidth() / 2 + item.offset)
        .attr('y2', (item) => y(item.label) + y.bandwidth() / 2 + item.offset)
        .attr('stroke', (item) =>
          item.series === 'actual' ? ACTUAL_COLOR : PROCESSED_COLOR
        )
        .attr('stroke-width', 2);
      const dots = svg.append('g').selectAll('circle').data(marks).join('circle')
        .attr('cx', (item) => x(item.value))
        .attr('cy', (item) => y(item.label) + y.bandwidth() / 2 + item.offset)
        .attr('r', (item) =>
          selectedItem?.chart === 'Covered CWE groups' &&
          selectedItem.series === item.series &&
          selectedItem.label === item.label ? 9 : 6
        )
        .attr('fill', '#111a2e')
        .attr('stroke', (item) =>
          item.series === 'actual' ? ACTUAL_COLOR : PROCESSED_COLOR
        )
        .attr('stroke-width', 4)
        .attr('opacity', (item) =>
          selectedItem?.chart === 'Covered CWE groups' &&
          (selectedItem.series !== item.series ||
            selectedItem.label !== item.label) ? 0.25 : 1
        )
        .style('cursor', 'pointer')
        .on('pointermove', (event, item) =>
          showTooltip(tooltip, event, item, 'samples')
        )
        .on('pointerleave', () => tooltip.classed('is-visible', false));

      makeInteractive(
        dots,
        (item) => `${item.series}, ${item.label}, ${formatNumber(item.value)} samples`,
        (item) => onSelect({
            chart: 'Covered CWE groups',
            series: item.series,
            label: item.label,
            value: item.value,
            unit: 'samples',
            total: totals[item.series],
          })
      );

      svg.append('g').selectAll('text').data(marks).join('text')
        .attr('class', 'statistics-lollipop-value')
        .attr('fill', (item) =>
          item.series === 'actual' ? ACTUAL_COLOR : PROCESSED_COLOR
        )
        .attr('x', (item) => {
          const endpoint = x(item.value);
          return endpoint > width - margin.right - 55
            ? endpoint - 11
            : endpoint + 11;
        })
        .attr('y', (item) => y(item.label) + y.bandwidth() / 2 + item.offset + 4)
        .attr('text-anchor', (item) =>
          x(item.value) > width - margin.right - 55 ? 'end' : 'start'
        )
        .text((item) => formatNumber(item.value));
    },
    JSON.stringify({ rows, selectedItem })
  );

  return (
    <ChartContainer
      chartRef={chartRef}
      className="statistics-lollipop-chart"
      label="Covered CWE groups lollipop chart"
    />
  );
}

function ModelComparisonChart({
  data,
  metric,
  selectedItem,
  onSelect,
}) {
  // Ranks Assignment 2 baseline models by the selected evaluation metric.
  const metricLabel =
    MODEL_METRICS.find((item) => item.key === metric)?.label || 'Score';
  const rankedModels = useMemo(
    () => [...(data || [])].sort((a, b) => b[metric] - a[metric]),
    [data, metric]
  );
  const chartRef = useChart(
    (container) => {
      const width = Math.max(container.clientWidth, 320);
      const height = Math.max(rankedModels.length * 58 + 30, 320);
      const margin = {
        top: 10,
        right: width < 560 ? 58 : 76,
        bottom: 20,
        left: width < 560 ? 116 : 168,
      };
      const x = d3.scaleLinear().domain([0, 1])
        .range([margin.left, width - margin.right]);
      const y = d3.scaleBand()
        .domain(rankedModels.map((item) => item.model))
        .range([margin.top, height - margin.bottom])
        .padding(0.34);
      const svg = d3.select(container).selectAll('svg').data([null]).join('svg')
        .attr('aria-label', `${metricLabel} model comparison chart`)
        .attr('viewBox', `0 0 ${width} ${height}`).attr('role', 'img');
      svg.selectAll('*').remove();
      const tooltip = d3.select(container).select('.statistics-tooltip');
      const rows = svg.selectAll('g').data(rankedModels).join('g')
        .attr('transform', (item) => `translate(0,${y(item.model)})`);

      rows.append('text')
        .attr('class', 'statistics-model-label')
        .attr('x', margin.left - 12)
        .attr('y', y.bandwidth() / 2)
        .attr('text-anchor', 'end')
        .attr('dominant-baseline', 'middle')
        .text((item, index) => `${index + 1}. ${item.model}`);

      const bars = rows.append('rect')
        .attr('x', margin.left)
        .attr('height', y.bandwidth())
        .attr('rx', 5)
        .attr('fill', (_, index) => index === 0 ? '#2dd4a8' : '#7c6cff')
        .attr('width', 0)
        .attr('opacity', (item) =>
          selectedItem?.chart === 'Model performance' &&
          selectedItem.label !== item.model ? 0.3 : 1
        )
        .style('cursor', 'pointer')
        .on('pointermove', (event, item) =>
          showTooltip(
            tooltip,
            event,
            { label: `${item.model} · ${metricLabel}`, value: item[metric] * 100 },
            '%'
          )
        )
        .on('pointerleave', () => tooltip.classed('is-visible', false));

      makeInteractive(
        bars,
        (item) => `${item.model}, ${metricLabel}, ${(item[metric] * 100).toFixed(2)}%`,
        (item) => onSelect({
            chart: 'Model performance',
            series: 'model',
            label: item.model,
            value: item[metric] * 100,
            unit: '%',
            total: 100,
          })
      );

      bars.transition().duration(600)
        .attr('width', (item) => x(item[metric]) - margin.left);

      rows.append('text')
        .attr('class', 'statistics-model-value')
        .attr('x', (item) => Math.min(x(item[metric]) + 9, width - 43))
        .attr('y', y.bandwidth() / 2)
        .attr('dominant-baseline', 'middle')
        .text((item) => `${(item[metric] * 100).toFixed(2)}%`);
    },
    JSON.stringify({ rankedModels, metric, selectedItem })
  );

  return (
    <ChartContainer
      chartRef={chartRef}
      className="statistics-model-chart"
      label={`${metricLabel} model comparison chart`}
    />
  );
}

function Statistics() {
  // Page state: dataset summary from the backend, selected chart item, metric.
  const [summary, setSummary] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState('');
  const [selectedItem, setSelectedItem] = useState(null);
  const [selectedMetric, setSelectedMetric] = useState('accuracy');

  useEffect(() => {
    // Load all data needed by the Statistics page from the FastAPI backend.
    let isMounted = true;
    fetch(`${API_BASE_URL}/visualizations/dataset-summary`)
      .then((response) => {
        if (!response.ok) throw new Error('Unable to load the dataset summary.');
        return response.json();
      })
      .then((data) => {
        if (isMounted) {
          setSummary(data);
          setErrorMessage('');
        }
      })
      .catch((error) => {
        if (isMounted) setErrorMessage(error.message);
      })
      .finally(() => {
        if (isMounted) setIsLoading(false);
      });
    return () => { isMounted = false; };
  }, []);

  const actual = summary?.training;
  const processed = summary?.processed_training;
  const evaluation = summary?.evaluation;
  const processedEvaluation = summary?.processed_evaluation;
  const modelComparison = summary?.model_comparison || [];
  const selectedMetricLabel =
    MODEL_METRICS.find((item) => item.key === selectedMetric)?.label;
  const leadingModel = [...modelComparison].sort(
    (a, b) => b[selectedMetric] - a[selectedMetric]
  )[0];

  function handleSelect(item) {
    // Clicking the same chart item twice clears the selection panel.
    const isSame =
      selectedItem?.chart === item.chart &&
      selectedItem?.series === item.series &&
      selectedItem?.label === item.label;
    setSelectedItem(isSame ? null : item);
  }

  if (isLoading) {
    return (
      <main className="statistics-page">
        <header className="statistics-header">
          <div className="statistics-title">
            <h1>Dataset Statistics</h1>
            <p>Explore the data used to train and evaluate our vulnerability detection models.</p>
          </div>
          <div className="statistics-connection">
            <span />
            Loading dataset summary
          </div>
        </header>
        <section aria-label="Loading statistics" className="statistics-skeleton">
          <div className="statistics-skeleton-overview">
            {[0, 1, 2, 3].map((item) => <i key={item} />)}
          </div>
          <div className="statistics-skeleton-panel" />
          <div className="statistics-skeleton-grid">
            <i />
            <i />
          </div>
        </section>
      </main>
    );
  }

  return (
    <main className="statistics-page">
      <header className="statistics-header">
        <div className="statistics-title">
          <h1>Dataset Statistics</h1>
          <p>Explore the data used to train and evaluate our vulnerability detection models.</p>
        </div>
        <div className={`statistics-connection ${errorMessage ? 'statistics-connection-error' : ''}`}>
          <span />
          {isLoading && 'Loading dataset summary'}
          {!isLoading && errorMessage && 'Dataset API unavailable'}
          {!isLoading && !errorMessage && 'Dataset API connected'}
        </div>
      </header>

      {errorMessage && (
        <section className="statistics-alert">
          <strong>Dataset summary could not be loaded.</strong>
          <span>{errorMessage} Start FastAPI and refresh this page.</span>
        </section>
      )}

      <section className="statistics-data-flow" aria-label="Dataset processing flow">
        {[
          ['01', 'Original Training', actual?.total_samples, 'Raw combined dataset'],
          ['02', 'Model Input', processed?.total_samples, 'Balanced training sample'],
          ['03', 'Evaluation', evaluation?.total_samples, 'Validation and ZEN data'],
          ['04', 'Balanced Evaluation', processedEvaluation?.total_samples, 'Final test sample'],
        ].map(([step, label, value, note]) => (
          <article key={label}>
            <span className="statistics-flow-step">{step}</span>
            <div>
              <span>{label}</span>
              <strong>{formatNumber(value)}</strong>
              <small>{note}</small>
            </div>
          </article>
        ))}
      </section>

      {selectedItem && (
        <section className="statistics-selection" aria-live="polite">
          <div>
            <p>{selectedItem.chart}</p>
            <h2>{selectedItem.label}</h2>
            <span>
              {selectedItem.series === 'actual'
                ? 'Actual Dataset'
                : selectedItem.series === 'processed'
                ? 'Model-Processed'
                : 'Assignment 2 Model'}
            </span>
          </div>
          <div className="statistics-selection-values">
            <strong>{formatNumber(selectedItem.value)}</strong>
            <span>{selectedItem.unit}</span>
            <small>
              {selectedItem.series === 'model'
                ? 'Selected performance score'
                : `${((selectedItem.value / selectedItem.total) * 100).toFixed(1)}% of this dataset`}
            </small>
            <button
              aria-label="Close selected data"
              onClick={() => setSelectedItem(null)}
              title="Close"
              type="button"
            >
              ×
            </button>
          </div>
        </section>
      )}

      <section className="statistics-layout">
        <article className="statistics-panel statistics-panel-wide">
          <div className="statistics-panel-heading">
            <div><p>Training Set</p><h2>Vulnerability Label Distribution</h2></div>
            <span>{formatNumber(actual?.total_samples)} vs {formatNumber(processed?.total_samples)}</span>
          </div>
          <div className="statistics-comparison-grid">
            <DonutChart
              title="Actual Dataset"
              series="actual"
              data={actual?.label_counts}
              selectedItem={selectedItem}
              onSelect={handleSelect}
            />
            <DonutChart
              title="Model-Processed"
              series="processed"
              data={processed?.label_counts}
              selectedItem={selectedItem}
              onSelect={handleSelect}
            />
          </div>
        </article>

        <article className="statistics-panel">
          <div className="statistics-panel-heading">
            <div><p>Dataset Composition</p><h2>Samples by Source</h2></div>
          </div>
          <GroupedColumnChart
            actualData={actual?.source_counts}
            processedData={processed?.source_counts}
            chartName="Dataset sources"
            unit="samples"
            selectedItem={selectedItem}
            onSelect={handleSelect}
          />
        </article>

        <article className="statistics-panel">
          <div className="statistics-panel-heading">
            <div><p>Model Scope</p><h2>Covered CWE Groups</h2></div>
          </div>
          <LollipopChart
            actualData={actual?.cwe_counts}
            processedData={processed?.cwe_counts}
            selectedItem={selectedItem}
            onSelect={handleSelect}
          />
          <p className="statistics-panel-note">
            SARD is removed before the 60,000-per-class sample; unsupported CWE
            IDs remain grouped into <strong>CWE-OTHERS</strong>.
          </p>
        </article>

        <article className="statistics-panel statistics-panel-wide statistics-model-panel">
          <div className="statistics-panel-heading statistics-model-heading">
            <div>
              <p>Assignment 2 Traditional Baselines</p>
              <h2>Traditional Model Comparison</h2>
            </div>
            <div className="statistics-metric-control" aria-label="Performance metric">
              {MODEL_METRICS.map((metric) => (
                <button
                  className={selectedMetric === metric.key ? 'is-active' : ''}
                  key={metric.key}
                  onClick={() => {
                    setSelectedMetric(metric.key);
                    setSelectedItem(null);
                  }}
                  type="button"
                >
                  {metric.label}
                </button>
              ))}
            </div>
          </div>
          <div className="statistics-model-summary">
            <div>
              <span>Leading model</span>
              <strong className="statistics-summary-updated" key={`${selectedMetric}-model`}>
                {leadingModel?.model || 'Loading'}
              </strong>
            </div>
            <div>
              <span>{selectedMetricLabel}</span>
              <strong className="statistics-summary-updated" key={`${selectedMetric}-score`}>
                {leadingModel ? `${(leadingModel[selectedMetric] * 100).toFixed(2)}%` : '0%'}
              </strong>
            </div>
            <div>
              <span>Traditional models evaluated</span>
              <strong>{modelComparison.length}</strong>
            </div>
          </div>
          <ModelComparisonChart
            data={modelComparison}
            metric={selectedMetric}
            selectedItem={selectedItem}
            onSelect={handleSelect}
          />
          <p className="statistics-panel-note">
            These five scores cover the traditional baseline models evaluated
            on the balanced 24,848-sample set in
            <strong> baseline_binary.ipynb</strong>. Handcrafted-feature and
            CodeBERT experiments use separate evaluation results.
          </p>
        </article>
      </section>

    </main>
  );
}

export default Statistics;
