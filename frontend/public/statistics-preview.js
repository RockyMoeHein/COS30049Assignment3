const API_URL = 'http://127.0.0.1:8000';
const BLUE = '#2997ff';
const PURPLE = '#8b7cf6';
const number = new Intl.NumberFormat('en-US');

const metricNames = {
  accuracy: 'Accuracy',
  vulnerable_precision: 'Vulnerable Precision',
  vulnerable_recall: 'Vulnerable Recall',
  vulnerable_f1: 'Vulnerable F1',
  macro_f1: 'Macro F1',
};

let summary;
let selected;
let selectedMetric = 'accuracy';

function setText(id, value) {
  document.getElementById(id).textContent = value;
}

function comparisonRows(actual = {}, processed = {}) {
  const labels = [...new Set([...Object.keys(actual), ...Object.keys(processed)])];
  return labels.map((label) => ({
    label: label.replaceAll('_', ' '),
    actual: actual[label] || 0,
    processed: processed[label] || 0,
  }));
}

function addTooltip(marks, container, unit) {
  const tooltip = d3.select(container).select('.tooltip');

  marks
    .on('pointermove', (event, item) => {
      const value = item.data || item;
      tooltip
        .classed('visible', true)
        .style('left', `${event.offsetX + 12}px`)
        .style('top', `${event.offsetY - 10}px`)
        .html(`<strong>${value.label}</strong><span>${number.format(value.value)} ${unit}</span>`);
    })
    .on('pointerleave', () => tooltip.classed('visible', false));
}

function chooseItem(item) {
  const sameItem = selected
    && selected.chart === item.chart
    && selected.series === item.series
    && selected.label === item.label;

  selected = sameItem ? null : item;
  updateSelection();
  drawCharts();
}

function updateSelection() {
  const values = document.getElementById('selectionValues');

  if (!selected) {
    setText('selectedLabel', 'Click any chart item');
    setText('selectedChart', 'Select a chart item to inspect its value.');
    values.classList.add('hidden');
    return;
  }

  const source = selected.series === 'actual'
    ? 'Actual Dataset'
    : selected.series === 'processed'
      ? 'Model-Processed'
      : 'Assignment 2';

  setText('selectedLabel', selected.label);
  setText('selectedChart', `${source} · ${selected.chart}`);
  setText('selectedValue', number.format(selected.value));
  setText('selectedUnit', selected.unit);
  setText(
    'selectedPercent',
    selected.series === 'model'
      ? 'Selected performance score'
      : `${(selected.value / selected.total * 100).toFixed(1)}% of this dataset`
  );
  values.classList.remove('hidden');
}

function drawDonut(id, data, series) {
  const container = document.getElementById(id);
  const size = Math.min(container.clientWidth, 230);
  const radius = size / 2;
  const values = [
    { label: 'Vulnerable', value: data.VULNERABLE || 0, color: '#ff6b7a' },
    { label: 'Non-vulnerable', value: data.NON_VULNERABLE || 0, color: '#2dd4a8' },
  ];
  const total = d3.sum(values, (item) => item.value);

  const svg = d3.select(container).selectAll('svg').data([null]).join('svg')
    .attr('viewBox', `0 0 ${size} ${size}`);
  svg.selectAll('*').remove();

  const group = svg.append('g').attr('transform', `translate(${radius},${radius})`);
  const arc = d3.arc().innerRadius(radius * 0.62).outerRadius(radius * 0.92).cornerRadius(5);
  const pie = d3.pie().sort(null).value((item) => item.value);

  const slices = group.selectAll('path').data(pie(values)).join('path')
    .attr('d', arc)
    .attr('fill', (item) => item.data.color)
    .attr('stroke', '#111a2e')
    .attr('stroke-width', 3)
    .attr('opacity', (item) => (
      selected?.series === series && selected.label !== item.data.label ? 0.35 : 1
    ))
    .style('cursor', 'pointer')
    .on('click', (_, item) => chooseItem({
      chart: 'Vulnerability labels',
      series,
      label: item.data.label,
      value: item.data.value,
      unit: 'samples',
      total,
    }));

  addTooltip(slices, container, 'samples');

  group.append('text').attr('class', 'donut-value')
    .attr('text-anchor', 'middle').attr('y', -2)
    .text(`${total ? (values[0].value / total * 100).toFixed(1) : 0}%`);
  group.append('text').attr('class', 'donut-label')
    .attr('text-anchor', 'middle').attr('y', 20)
    .text('vulnerable');
}

function drawSourceChart(actual, processed) {
  const container = document.getElementById('sourceChart');
  const data = comparisonRows(actual, processed);
  const width = Math.max(container.clientWidth, 300);
  const height = 270;
  const margin = { top: 18, right: 16, bottom: 62, left: 58 };
  const totals = {
    actual: d3.sum(data, (item) => item.actual),
    processed: d3.sum(data, (item) => item.processed),
  };

  const x = d3.scaleBand().domain(data.map((item) => item.label))
    .range([margin.left, width - margin.right]).padding(0.2);
  const seriesX = d3.scaleBand().domain(['actual', 'processed'])
    .range([0, x.bandwidth()]).padding(0.08);
  const maximum = d3.max(data, (item) => Math.max(item.actual, item.processed)) || 1;
  const y = d3.scaleLinear().domain([0, maximum]).nice()
    .range([height - margin.bottom, margin.top]);

  const svg = d3.select(container).selectAll('svg').data([null]).join('svg')
    .attr('viewBox', `0 0 ${width} ${height}`);
  svg.selectAll('*').remove();

  svg.append('g').attr('class', 'grid')
    .attr('transform', `translate(${margin.left},0)`)
    .call(d3.axisLeft(y).ticks(4).tickSize(-(width - margin.left - margin.right)).tickFormat(''));
  svg.append('g').attr('class', 'axis')
    .attr('transform', `translate(0,${height - margin.bottom})`)
    .call(d3.axisBottom(x).tickSize(0));
  svg.append('g').attr('class', 'axis')
    .attr('transform', `translate(${margin.left},0)`)
    .call(d3.axisLeft(y).ticks(4).tickFormat(d3.format('~s')));

  const marks = data.flatMap((item) => [
    { label: item.label, value: item.actual, series: 'actual' },
    { label: item.label, value: item.processed, series: 'processed' },
  ]);

  const bars = svg.append('g').selectAll('rect').data(marks).join('rect')
    .attr('x', (item) => x(item.label) + seriesX(item.series))
    .attr('y', (item) => y(item.value))
    .attr('width', seriesX.bandwidth())
    .attr('height', (item) => height - margin.bottom - y(item.value))
    .attr('rx', 4)
    .attr('fill', (item) => item.series === 'actual' ? BLUE : PURPLE)
    .style('cursor', 'pointer')
    .on('click', (_, item) => chooseItem({
      chart: 'Dataset sources',
      ...item,
      unit: 'samples',
      total: totals[item.series],
    }));

  addTooltip(bars, container, 'samples');
}

function drawCweChart(actual, processed) {
  const container = document.getElementById('cweChart');
  const data = comparisonRows(actual, processed);
  const width = Math.max(container.clientWidth, 300);
  const height = Math.max(data.length * 56 + 42, 150);
  const margin = { top: 36, right: 86, bottom: 8, left: 126 };
  const totals = {
    actual: d3.sum(data, (item) => item.actual),
    processed: d3.sum(data, (item) => item.processed),
  };

  const maximum = d3.max(data, (item) => Math.max(item.actual, item.processed)) || 1;
  const x = d3.scaleLinear().domain([0, maximum]).range([margin.left, width - margin.right]);
  const y = d3.scaleBand().domain(data.map((item) => item.label))
    .range([margin.top, height - margin.bottom]).padding(0.35);

  const svg = d3.select(container).selectAll('svg').data([null]).join('svg')
    .attr('viewBox', `0 0 ${width} ${height}`);
  svg.selectAll('*').remove();

  const labels = svg.append('g').selectAll('text').data(data).join('text')
    .attr('class', 'axis-label')
    .attr('x', margin.left - 12)
    .attr('y', (item) => y(item.label) + y.bandwidth() / 2)
    .attr('text-anchor', 'end')
    .attr('dominant-baseline', 'middle')
    .text((item) => item.label);

  const marks = data.flatMap((item) => [
    { label: item.label, value: item.actual, series: 'actual', offset: -6 },
    { label: item.label, value: item.processed, series: 'processed', offset: 6 },
  ]);

  svg.append('g').selectAll('line').data(marks).join('line')
    .attr('x1', margin.left).attr('x2', (item) => x(item.value))
    .attr('y1', (item) => y(item.label) + y.bandwidth() / 2 + item.offset)
    .attr('y2', (item) => y(item.label) + y.bandwidth() / 2 + item.offset)
    .attr('stroke', (item) => item.series === 'actual' ? BLUE : PURPLE)
    .attr('stroke-width', 2);

  const dots = svg.append('g').selectAll('circle').data(marks).join('circle')
    .attr('cx', (item) => x(item.value))
    .attr('cy', (item) => y(item.label) + y.bandwidth() / 2 + item.offset)
    .attr('r', 6)
    .attr('fill', '#111a2e')
    .attr('stroke', (item) => item.series === 'actual' ? BLUE : PURPLE)
    .attr('stroke-width', 4)
    .style('cursor', 'pointer')
    .on('click', (_, item) => chooseItem({
      chart: 'Covered CWE groups',
      ...item,
      unit: 'samples',
      total: totals[item.series],
    }));

  addTooltip(dots, container, 'samples');
  labels.raise();
}

function drawModelChart() {
  const container = document.getElementById('modelChart');
  const data = [...summary.model_comparison]
    .sort((a, b) => b[selectedMetric] - a[selectedMetric]);
  const width = Math.max(container.clientWidth, 320);
  const height = Math.max(data.length * 58 + 30, 320);
  const margin = { top: 10, right: 76, bottom: 20, left: 168 };

  const x = d3.scaleLinear().domain([0, 1]).range([margin.left, width - margin.right]);
  const y = d3.scaleBand().domain(data.map((item) => item.model))
    .range([margin.top, height - margin.bottom]).padding(0.34);

  const svg = d3.select(container).selectAll('svg').data([null]).join('svg')
    .attr('viewBox', `0 0 ${width} ${height}`);
  svg.selectAll('*').remove();

  const rows = svg.selectAll('g').data(data).join('g')
    .attr('transform', (item) => `translate(0,${y(item.model)})`);

  rows.append('text').attr('class', 'model-label')
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
    .style('cursor', 'pointer')
    .on('click', (_, item) => chooseItem({
      chart: 'Model performance',
      series: 'model',
      label: item.model,
      value: item[selectedMetric] * 100,
      unit: '%',
      total: 100,
    }));

  bars.transition().duration(600)
    .attr('width', (item) => x(item[selectedMetric]) - margin.left);

  const tooltip = d3.select(container).select('.tooltip');
  bars
    .on('pointermove', (event, item) => {
      tooltip
        .classed('visible', true)
        .style('left', `${event.offsetX + 12}px`)
        .style('top', `${event.offsetY - 10}px`)
        .html(
          `<strong>${item.model} · ${metricNames[selectedMetric]}</strong>`
          + `<span>${(item[selectedMetric] * 100).toFixed(2)}%</span>`
        );
    })
    .on('pointerleave', () => tooltip.classed('visible', false));

  rows.append('text').attr('class', 'model-value')
    .attr('x', (item) => Math.min(x(item[selectedMetric]) + 9, width - 43))
    .attr('y', y.bandwidth() / 2)
    .attr('dominant-baseline', 'middle')
    .text((item) => `${(item[selectedMetric] * 100).toFixed(2)}%`);

  setText('leadingModel', data[0]?.model || 'Loading');
  setText('leadingMetric', metricNames[selectedMetric]);
  setText('leadingScore', data[0] ? `${(data[0][selectedMetric] * 100).toFixed(2)}%` : '0%');
  setText('modelCount', data.length);
}

function drawCharts() {
  const actual = summary.training;
  const processed = summary.processed_training;
  drawDonut('actualDonut', actual.label_counts, 'actual');
  drawDonut('processedDonut', processed.label_counts, 'processed');
  drawSourceChart(actual.source_counts, processed.source_counts);
  drawCweChart(actual.cwe_counts, processed.cwe_counts);
  drawModelChart();
}

function showSummary() {
  const actual = summary.training;
  const processed = summary.processed_training;

  setText('rawTraining', number.format(actual.total_samples));
  setText('processedTraining', number.format(processed.total_samples));
  setText('actualEvaluation', number.format(summary.evaluation.total_samples));
  setText('processedEvaluation', number.format(summary.processed_evaluation.total_samples));
  setText('labelBadge', `${number.format(actual.total_samples)} vs ${number.format(processed.total_samples)}`);
  setText('actualVulnerable', number.format(actual.label_counts.VULNERABLE));
  setText('actualSafe', number.format(actual.label_counts.NON_VULNERABLE));
  setText('processedVulnerable', number.format(processed.label_counts.VULNERABLE));
  setText('processedSafe', number.format(processed.label_counts.NON_VULNERABLE));
  drawCharts();
}

fetch(`${API_URL}/visualizations/dataset-summary`)
  .then((response) => {
    if (!response.ok) throw new Error('Unable to load the dataset summary.');
    return response.json();
  })
  .then((data) => {
    summary = data;
    setText('connectionText', 'Dataset API connected');
    showSummary();
  })
  .catch((error) => {
    document.getElementById('connection').classList.add('error');
    setText('connectionText', 'Dataset API unavailable');
    const alert = document.getElementById('alert');
    alert.textContent = `${error.message} Start FastAPI and refresh this page.`;
    alert.classList.remove('hidden');
  });

document.getElementById('clearSelection').addEventListener('click', () => {
  selected = null;
  updateSelection();
  drawCharts();
});

document.querySelectorAll('#metricControl button').forEach((button) => {
  button.addEventListener('click', () => {
    document.querySelector('#metricControl .active').classList.remove('active');
    button.classList.add('active');
    selectedMetric = button.dataset.metric;
    selected = null;
    updateSelection();
    drawModelChart();
  });
});

let resizeTimer;
window.addEventListener('resize', () => {
  clearTimeout(resizeTimer);
  resizeTimer = setTimeout(() => summary && drawCharts(), 150);
});
