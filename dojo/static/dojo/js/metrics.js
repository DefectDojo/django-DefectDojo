/**
 * DefectDojo Chart Rendering — Chart.js v4
 *
 * Drop-in replacement for the legacy Flot-based charting.
 * Every public function signature is preserved so that Django templates
 * continue to work without modification.
 *
 * Depends on:
 *   - chart.js (^4.4)
 *   - chartjs-adapter-moment (^1.0)
 *   - moment (^2.30)  (already a project dependency)
 */

/* ──────────────────────────────────────────────────────────────────
   Chart instance registry — tracks instances so we can destroy
   before re-creating (avoids memory leaks on page reload / AJAX).
   ────────────────────────────────────────────────────────────────── */
const _chartInstances = {};

/* ──────────────────────────────────────────────────────────────────
   Severity colour palette (updated to match Tailwind design tokens)
   ────────────────────────────────────────────────────────────────── */
const SEV = {
    critical: '#dc2626',   // red-600
    high:     '#ea580c',   // orange-600
    medium:   '#ca8a04',   // yellow-600
    low:      '#2563eb',   // blue-600
    info:     '#6b7280',   // gray-500
    green:    '#16a34a',   // green-600  (used in burndown low)
    accepted: '#7c3aed',   // violet-600 (accepted / info alternate)
};

/* ──────────────────────────────────────────────────────────────────
   Helpers
   ────────────────────────────────────────────────────────────────── */

/** Ensure a <canvas> exists inside the target container div. */
function _ensureCanvas(selector) {
    let el;
    if (typeof selector === 'string') {
        el = document.querySelector(selector);
        if (!el) el = document.getElementById(selector.replace(/^#/, ''));
    } else {
        el = selector;
    }
    if (!el) return null;

    let canvas = el.querySelector('canvas');
    if (!canvas) {
        canvas = document.createElement('canvas');
        el.innerHTML = '';
        el.appendChild(canvas);
    }
    return canvas;
}

/** Destroy a previously-created chart for the given container id. */
function _destroyChart(id) {
    const key = id.replace(/^#/, '');
    if (_chartInstances[key]) {
        _chartInstances[key].destroy();
        delete _chartInstances[key];
    }
}

/** Create a Chart.js instance, register it in the registry. */
function _createChart(containerId, config) {
    const canvas = _ensureCanvas(containerId);
    if (!canvas) return null;

    const key = containerId.replace(/^#/, '');
    _destroyChart(key);

    const chart = new Chart(canvas.getContext('2d'), config);
    _chartInstances[key] = chart;
    return chart;
}

/** Convert Flot time-series [[ts, val], …] → Chart.js [{x, y}, …] */
function _toTimePoints(data) {
    return (data || []).map(function (d) { return { x: d[0], y: d[1] }; });
}

/** Extract just the y-values from [[idx, val], …] */
function _vals(data) {
    return (data || []).map(function (d) { return d[1]; });
}

/** Extract label strings from Flot tick arrays.
 *  Accepts [[0,"Lbl"], …] or plain ["Lbl", …]. Strips embedded HTML. */
function _tickLabels(ticks) {
    if (!ticks || !ticks.length) return [];
    if (Array.isArray(ticks[0])) {
        return ticks.map(function (t) {
            var lbl = (t[1] != null) ? String(t[1]) : '';
            return lbl.replace(/<[^>]*>/g, ' ').trim();
        });
    }
    return ticks;
}

/* ──────────────────────────────────────────────────────────────────
   Dataset factory helpers
   ────────────────────────────────────────────────────────────────── */

function _timeDS(label, data, color) {
    return {
        label: label,
        data: _toTimePoints(data),
        borderColor: color,
        backgroundColor: color + '18',
        pointRadius: 3,
        pointHoverRadius: 5,
        borderWidth: 2,
        tension: 0.15,
        fill: false,
    };
}

function _tickDS(label, data, color) {
    return {
        label: label,
        data: _vals(data),
        borderColor: color,
        backgroundColor: color + '18',
        pointRadius: 3,
        pointHoverRadius: 5,
        borderWidth: 2,
        tension: 0.15,
        fill: false,
    };
}

/* ──────────────────────────────────────────────────────────────────
   Shared chart builders (private)
   ────────────────────────────────────────────────────────────────── */

/** Time-axis line chart (severity datasets). */
function _sevTimeLine(id, datasets, opts) {
    opts = opts || {};
    return _createChart(id, {
        type: 'line',
        data: { datasets: datasets },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                tooltip: { enabled: opts.tooltip !== false },
                legend: {
                    position: opts.legendPos || 'top',
                    labels: { usePointStyle: true, boxWidth: 8 },
                },
            },
            scales: {
                x: {
                    type: 'time',
                    time: {
                        tooltipFormat: opts.timeFmt || 'MM/DD/YYYY',
                        unit: opts.timeUnit,
                    },
                    ticks: { maxTicksLimit: opts.maxTicks },
                    grid: { color: '#e5e7eb' },
                },
                y: {
                    beginAtZero: true,
                    min: opts.yMin,
                    max: opts.yMax,
                    grid: { color: '#e5e7eb' },
                },
            },
        },
    });
}

/** Tick-label line chart (datasets already contain plain values). */
function _sevTickLine(id, datasets, labels, opts) {
    opts = opts || {};
    return _createChart(id, {
        type: 'line',
        data: { labels: labels, datasets: datasets },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            plugins: {
                tooltip: { enabled: opts.tooltip !== false },
                legend: {
                    position: 'top',
                    labels: { usePointStyle: true, boxWidth: 8 },
                },
            },
            scales: {
                x: {
                    grid: { color: '#e5e7eb' },
                    ticks: { maxRotation: 45, autoSkip: true },
                },
                y: {
                    beginAtZero: true,
                    grid: { color: '#e5e7eb' },
                },
            },
        },
    });
}

/** Stacked bar chart (5 severity datasets). */
function _sevStackedBar(id, d1, d2, d3, d4, d5, ticks, opts) {
    opts = opts || {};
    var labels = _tickLabels(ticks);
    return _createChart(id, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                { label: 'Critical', data: _vals(d1), backgroundColor: SEV.critical },
                { label: 'High',     data: _vals(d2), backgroundColor: SEV.high },
                { label: 'Medium',   data: _vals(d3), backgroundColor: SEV.medium },
                { label: 'Low',      data: _vals(d4), backgroundColor: SEV.low },
                { label: 'Info',     data: _vals(d5), backgroundColor: SEV.info },
            ],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                tooltip: { enabled: true },
                legend: {
                    display: opts.showLegend === true,
                    position: 'top',
                    labels: { usePointStyle: true, boxWidth: 8 },
                },
            },
            scales: {
                x: { stacked: true, grid: { display: false }, ticks: { maxRotation: 45, autoSkip: true } },
                y: { stacked: true, beginAtZero: true, grid: { color: '#e5e7eb' } },
            },
        },
    });
}

/** Pie / doughnut chart. items = [{label, value, color}, …] */
function _pie(id, items, opts) {
    opts = opts || {};
    return _createChart(id, {
        type: opts.donut ? 'doughnut' : 'pie',
        data: {
            labels: items.map(function (i) { return i.label; }),
            datasets: [{
                data: items.map(function (i) { return i.value; }),
                backgroundColor: items.map(function (i) { return i.color; }),
                borderWidth: 1,
                borderColor: '#fff',
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            cutout: opts.donut ? '50%' : 0,
            plugins: {
                tooltip: { enabled: true },
                legend: {
                    display: opts.showLegend !== false,
                    position: opts.legendPos || 'top',
                    container: opts.legendContainer,
                    labels: { usePointStyle: true, boxWidth: 10 },
                },
            },
        },
    });
}

/* ──────────────────────────────────────────────────────────────────
   Category bar chart helper (for test_type, draw_vulnerabilities_graph)
   Flot "categories" data format: [["Label1", val], ["Label2", val], …]
   ────────────────────────────────────────────────────────────────── */
function _categoryBar(id, data, opts) {
    opts = opts || {};
    var labels = (data || []).map(function (d) { return d[0]; });
    var values = (data || []).map(function (d) { return d[1]; });
    return _createChart(id, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: SEV.low,
                borderWidth: 0,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                tooltip: { enabled: true },
                legend: { display: false },
            },
            scales: {
                x: { grid: { display: false }, ticks: { maxRotation: 45, autoSkip: true } },
                y: { beginAtZero: true, grid: { color: '#e5e7eb' } },
            },
        },
    });
}


/* ══════════════════════════════════════════════════════════════════
   PUBLIC API — all function signatures preserved for templates
   ══════════════════════════════════════════════════════════════════ */

/*
 *  dashboard.html
 */

function homepage_pie_chart(critical, high, medium, low, info) {
    _pie('#homepage_pie_chart', [
        { label: 'Critical',      value: critical, color: SEV.critical },
        { label: 'High',          value: high,     color: SEV.high },
        { label: 'Medium',        value: medium,   color: SEV.medium },
        { label: 'Low',           value: low,      color: SEV.low },
        { label: 'Informational', value: info,     color: SEV.info },
    ], { donut: true });
}

function homepage_severity_plot(critical, high, medium, low) {
    _sevTimeLine('#homepage_severity_plot', [
        _timeDS('Critical', critical, SEV.critical),
        _timeDS('High',     high,     SEV.high),
        _timeDS('Medium',   medium,   SEV.medium),
        _timeDS('Low',      low,      SEV.low),
    ], { tooltip: true, timeUnit: 'month' });
}

/*
 *  dashboard-metrics.html
 */

function getTicks(critical, high, medium, low) {
    return [].concat(critical, high, medium, low)
        .map(function (x) { return x[0]; })
        .filter(function (v, i, a) { return a.indexOf(v) === i; });
}

function opened_per_month(critical, high, medium, low) {
    _sevTimeLine('#opened_per_month', [
        _timeDS('Critical', critical, SEV.critical),
        _timeDS('High',     high,     SEV.high),
        _timeDS('Medium',   medium,   SEV.medium),
        _timeDS('Low',      low,      SEV.low),
    ], { tooltip: false, timeFmt: 'MM/YY' });
}

function accepted_per_month(critical, high, medium, low) {
    _sevTimeLine('#accepted_per_month', [
        _timeDS('Critical', critical, SEV.critical),
        _timeDS('High',     high,     SEV.high),
        _timeDS('Medium',   medium,   SEV.medium),
        _timeDS('Low',      low,      SEV.low),
    ], { tooltip: false, timeFmt: 'MM/YY' });
}

function opened_per_week(critical, high, medium, low) {
    _sevTimeLine('#opened_per_week', [
        _timeDS('Critical', critical, SEV.critical),
        _timeDS('High',     high,     SEV.high),
        _timeDS('Medium',   medium,   SEV.medium),
        _timeDS('Low',      low,      SEV.low),
    ], { tooltip: true, timeFmt: 'MM/DD/YYYY' });
}

function accepted_per_week(critical, high, medium, low) {
    _sevTimeLine('#accepted_per_week', [
        _timeDS('Critical', critical, SEV.critical),
        _timeDS('High',     high,     SEV.high),
        _timeDS('Medium',   medium,   SEV.medium),
        _timeDS('Low',      low,      SEV.low),
    ], { tooltip: false, timeFmt: 'MM/DD/YYYY' });
}

function top_ten_products(critical, high, medium, low, ticks) {
    _sevStackedBar('#top-ten', critical, high, medium, low, [], ticks, { showLegend: true });
}

function severity_pie(critical, high, medium, low) {
    _pie('#opened_in_period', [
        { label: 'Critical', value: critical, color: SEV.critical },
        { label: 'High',     value: high,     color: SEV.high },
        { label: 'Medium',   value: medium,   color: SEV.medium },
        { label: 'Low',      value: low,      color: SEV.low },
    ]);
}

function total_accepted_pie(critical, high, medium, low) {
    _pie('#total_accepted_in_period', [
        { label: 'Critical', value: critical, color: SEV.critical },
        { label: 'High',     value: high,     color: SEV.high },
        { label: 'Medium',   value: medium,   color: SEV.medium },
        { label: 'Low',      value: low,      color: SEV.low },
    ]);
}

function total_closed_pie(critical, high, medium, low) {
    _pie('#total_closed_in_period', [
        { label: 'Critical', value: critical, color: SEV.critical },
        { label: 'High',     value: high,     color: SEV.high },
        { label: 'Medium',   value: medium,   color: SEV.medium },
        { label: 'Low',      value: low,      color: SEV.low },
    ]);
}

/*
 *  metrics.html
 */

function opened_per_month_2(critical, high, medium, low) {
    var maxTicks = critical.length < 7 ? critical.length : 7;
    _sevTimeLine('#opened_per_month_2', [
        _timeDS('Critical', critical, SEV.critical),
        _timeDS('High',     high,     SEV.high),
        _timeDS('Medium',   medium,   SEV.medium),
        _timeDS('Low',      low,      SEV.low),
    ], { tooltip: true, timeFmt: 'MM-DD-YYYY', maxTicks: maxTicks });
}

function active_per_month(critical, high, medium, low) {
    var maxTicks = critical.length < 7 ? critical.length : 7;
    _sevTimeLine('#active_per_month', [
        _timeDS('Critical', critical, SEV.critical),
        _timeDS('High',     high,     SEV.high),
        _timeDS('Medium',   medium,   SEV.medium),
        _timeDS('Low',      low,      SEV.low),
    ], { tooltip: true, timeFmt: 'MM-DD-YYYY', maxTicks: maxTicks });
}

function accepted_per_month_2(critical, high, medium, low) {
    var maxTicks = critical.length < 7 ? critical.length : 7;
    _sevTimeLine('#accepted_per_month_2', [
        _timeDS('Critical', critical, SEV.critical),
        _timeDS('High',     high,     SEV.high),
        _timeDS('Medium',   medium,   SEV.medium),
        _timeDS('Low',      low,      SEV.low),
    ], { tooltip: true, timeFmt: 'MM-DD-YYYY', maxTicks: maxTicks });
}

function opened_per_week_2(critical, high, medium, low) {
    _sevTimeLine('#opened_per_week_2', [
        _timeDS('Critical', critical, SEV.critical),
        _timeDS('High',     high,     SEV.high),
        _timeDS('Medium',   medium,   SEV.medium),
        _timeDS('Low',      low,      SEV.low),
    ], { tooltip: true, timeFmt: 'MM-DD-YYYY', maxTicks: 7 });
}

function accepted_per_week_2(critical, high, medium, low) {
    _sevTimeLine('#accepted_per_week_2', [
        _timeDS('Critical', critical, SEV.critical),
        _timeDS('High',     high,     SEV.high),
        _timeDS('Medium',   medium,   SEV.medium),
        _timeDS('Low',      low,      SEV.low),
    ], { tooltip: true, timeFmt: 'MM-DD-YYYY', maxTicks: 7 });
}

/*
 *  Punchcard accessibility table (shared across dashboard, product_metrics)
 *  This function does not use charts — it builds an HTML table for screen readers.
 */
function updatePunchcardTable(punchcardData, ticks) {
    var tableBody = document.querySelector('#punchcard-table tbody');
    if (!tableBody) return;

    var daysMap = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
    var formattedData = {};

    if (!punchcardData || punchcardData.length === 0 || !ticks || ticks.length === 0) return;

    var ticksMap = {};
    ticks.forEach(function (entry) {
        var weekIndex = String(entry[0]);
        var rawHtml = entry[1];
        var cleanDate = rawHtml.replace(/<\/?span[^>]*>/g, '').replace(/<br\s*\/?>/g, ' ').trim();
        ticksMap[weekIndex] = cleanDate;
    });

    var minWeekOffset = ticks[0][0];
    var maxWeekOffset = ticks[ticks.length - 1][0];

    for (var weekOffset = minWeekOffset; weekOffset <= maxWeekOffset; weekOffset++) {
        var formattedDate = ticksMap[String(weekOffset)] || 'Unknown Date';
        var formattedWeek = 'Week ' + (weekOffset - minWeekOffset + 1) + ', starting on ' + formattedDate;
        formattedData[formattedWeek] = {
            Monday: 0, Tuesday: 0, Wednesday: 0,
            Thursday: 0, Friday: 0, Saturday: 0, Sunday: 0
        };
    }

    punchcardData.forEach(function (entry) {
        var wOffset = entry[0];
        var day = daysMap[entry[1]];
        var value = entry[3] || 0;
        var fDate = ticksMap[String(wOffset)] || 'Unknown Date';
        var fWeek = 'Week ' + (wOffset - minWeekOffset + 1) + ', starting on ' + fDate;
        if (formattedData[fWeek]) {
            formattedData[fWeek][day] = value;
        }
    });

    Object.keys(formattedData).forEach(function (week) {
        var values = formattedData[week];
        var row = document.createElement('tr');
        row.innerHTML =
            '<td>' + week + '</td>' +
            '<td>' + (values.Monday || 0) + '</td>' +
            '<td>' + (values.Tuesday || 0) + '</td>' +
            '<td>' + (values.Wednesday || 0) + '</td>' +
            '<td>' + (values.Thursday || 0) + '</td>' +
            '<td>' + (values.Friday || 0) + '</td>' +
            '<td>' + (values.Saturday || 0) + '</td>' +
            '<td>' + (values.Sunday || 0) + '</td>';
        tableBody.appendChild(row);
    });
}

/*
 *  product_metrics.html
 */

function open_findings_burndown(critical, high, medium, low, info, y_max, y_min) {
    _sevTimeLine('#open_findings_burndown', [
        _timeDS('Critical', critical, SEV.critical),
        _timeDS('High',     high,     SEV.high),
        _timeDS('Medium',   medium,   SEV.medium),
        _timeDS('Low',      low,      SEV.green),
        _timeDS('Info',     info,     SEV.low),
    ], { tooltip: true, timeFmt: 'YYYY/MM/DD', legendPos: 'top', yMax: y_max, yMin: y_min });
}

function accepted_objs(d1, d2, d3, d4, d5, ticks) {
    _sevStackedBar('#accepted_objs', d1, d2, d3, d4, d5, ticks);
}

function inactive_objs(d1, d2, d3, d4, d5, ticks) {
    _sevStackedBar('#inactive_objs', d1, d2, d3, d4, d5, ticks);
}

function open_objs(d1, d2, d3, d4, d5, ticks) {
    _sevStackedBar('#open_objs', d1, d2, d3, d4, d5, ticks);
}

function false_positive_objs(d1, d2, d3, d4, d5, ticks) {
    _sevStackedBar('#false_positive_objs', d1, d2, d3, d4, d5, ticks);
}

function verified_objs(d1, d2, d3, d4, d5, ticks) {
    _sevStackedBar('#verified_objs', d1, d2, d3, d4, d5, ticks);
}

function out_of_scope_objs(d1, d2, d3, d4, d5, ticks) {
    _sevStackedBar('#out_of_scope_objs', d1, d2, d3, d4, d5, ticks);
}

function all_objs(d1, d2, d3, d4, d5, ticks) {
    _sevStackedBar('#all_objs', d1, d2, d3, d4, d5, ticks);
}

function closed_objs(d1, d2, d3, d4, d5, ticks) {
    _sevStackedBar('#closed_objs', d1, d2, d3, d4, d5, ticks);
}

function new_objs(d1, d2, d3, d4, d5, ticks) {
    _sevStackedBar('#new_objs', d1, d2, d3, d4, d5, ticks);
}

function open_close_weekly(opened, closed, accepted, ticks) {
    var labels = _tickLabels(ticks);
    _sevTickLine('#open_close_weekly', [
        _tickDS('Opened',   opened,   SEV.critical),
        _tickDS('Closed',   closed,   SEV.high),
        _tickDS('Accepted', accepted, SEV.accepted),
    ], labels, { tooltip: true });
}

function severity_weekly(critical, high, medium, low, info, ticks) {
    var labels = _tickLabels(ticks);
    _sevTickLine('#severity_weekly', [
        _tickDS('Critical', critical, SEV.critical),
        _tickDS('High',     high,     SEV.high),
        _tickDS('Medium',   medium,   SEV.medium),
        _tickDS('Low',      low,      SEV.low),
        _tickDS('Info',     info,     SEV.info),
    ], labels, { tooltip: true });
}

function severity_counts_weekly(critical, high, medium, ticks) {
    var labels = _tickLabels(ticks);

    _sevTickLine('#severity_critical', [
        _tickDS('Critical', critical, SEV.critical),
    ], labels, { tooltip: true });

    _sevTickLine('#severity_high', [
        _tickDS('High', high, SEV.high),
    ], labels, { tooltip: true });

    _sevTickLine('#severity_medium', [
        _tickDS('Medium', medium, SEV.medium),
    ], labels, { tooltip: true });
}

function test_type(data) {
    _categoryBar('#test_type', data);
}

function draw_vulnerabilities_graph(tag, data) {
    _categoryBar(tag, data);
}

/*
 *  view_engineer.html
 */

function open_bug_count_by_month(critical, high, medium, low, ticks) {
    _sevTickLine('#chart_div', [
        _tickDS('Critical', critical, SEV.critical),
        _tickDS('High',     high,     SEV.high),
        _tickDS('Medium',   medium,   SEV.medium),
        _tickDS('Low',      low,      SEV.low),
    ], ticks, { tooltip: false });
}

function accepted_bug_count_by_month(critical, high, medium, low, ticks) {
    _sevTickLine('#chart_div2', [
        _tickDS('Critical', critical, SEV.critical),
        _tickDS('High',     high,     SEV.high),
        _tickDS('Medium',   medium,   SEV.medium),
        _tickDS('Low',      low,      SEV.low),
    ], ticks, { tooltip: false });
}

function open_bug_count_by_week(critical, high, medium, low, ticks) {
    _sevTickLine('#chart_div3', [
        _tickDS('Critical', critical, SEV.critical),
        _tickDS('High',     high,     SEV.high),
        _tickDS('Medium',   medium,   SEV.medium),
        _tickDS('Low',      low,      SEV.low),
    ], ticks, { tooltip: false });
}

function accepted_bug_count_by_week(critical, high, medium, low, ticks) {
    _sevTickLine('#chart_div4', [
        _tickDS('Critical', critical, SEV.critical),
        _tickDS('High',     high,     SEV.high),
        _tickDS('Medium',   medium,   SEV.medium),
        _tickDS('Low',      low,      SEV.low),
    ], ticks, { tooltip: false });
}

/*
 *  view_product_details.html
 */

function languages_pie(data) {
    // Flot format: [{label:"Go", data:42, color:"#xxx"}, …]
    // Also support pre-formatted Chart.js data
    if (!data || !data.length) return;
    _pie('#donut-lang', data.map(function (d) {
        return { label: d.label, value: d.data, color: d.color };
    }), { donut: true, legendPos: 'right' });
}

/*
 *  PDF report templates (endpoint_pdf, engagement_pdf, finding_pdf, product_pdf, etc.)
 */

function accepted_findings(d1, d2, d3, d4, d5, ticks) {
    _sevStackedBar('#accepted_findings', d1, d2, d3, d4, d5, ticks);
}

function finding_age(data_1, ticks) {
    var labels = _tickLabels(ticks);
    _createChart('#finding_age', {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: 'Findings',
                data: _vals(data_1),
                backgroundColor: SEV.low,
                borderWidth: 0,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: { enabled: true },
            },
            scales: {
                x: {
                    title: { display: true, text: 'Days Open' },
                    grid: { display: false },
                    ticks: { maxRotation: 45 },
                },
                y: {
                    title: { display: true, text: 'Number of Findings' },
                    beginAtZero: true,
                    grid: { color: '#e5e7eb' },
                },
            },
        },
    });
}

function open_findings(d1, d2, d3, d4, d5, ticks) {
    _sevStackedBar('#open_findings', d1, d2, d3, d4, d5, ticks);
}

function closed_findings(d1, d2, d3, d4, d5, ticks) {
    _sevStackedBar('#closed_findings', d1, d2, d3, d4, d5, ticks);
}

/*
 *  Punchcard (bubble chart) — replaces JUMFlot bubbles.
 *  Formerly in index.js, moved here to co-locate all chart code.
 *
 *  Flot data:  [[weekOffset, dayIndex, 0, count], …]
 *  Chart.js:   [{x: weekOffset, y: dayIndex, r: scaled_radius}, …]
 */
function punchcard(element, data, ticks) {
    if (!data || !data.length) return;

    // Find max count for radius scaling
    var maxCount = 1;
    data.forEach(function (d) {
        if (d[3] > maxCount) maxCount = d[3];
    });

    var bubbleData = data.map(function (d) {
        return {
            x: d[0],
            y: d[1],
            r: Math.max(2, Math.sqrt(d[3] / maxCount) * 18),
            _count: d[3],
        };
    });

    var tickLabels = _tickLabels(ticks);

    // Day labels (Flot had [6,'Sun'],[5,'Mon'],… — reverse Y order)
    var dayLabels = ['Sat', 'Fri', 'Thur', 'Wed', 'Tue', 'Mon', 'Sun'];

    _createChart(element, {
        type: 'bubble',
        data: {
            datasets: [{
                data: bubbleData,
                backgroundColor: 'rgba(99, 102, 241, 0.5)',
                borderColor: 'rgb(99, 102, 241)',
                borderWidth: 1,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function (ctx) {
                            return (ctx.raw._count || 0) + ' Findings';
                        },
                    },
                },
            },
            scales: {
                x: {
                    min: -0.8,
                    max: ticks.length - 0.2,
                    ticks: {
                        callback: function (value) {
                            return tickLabels[value] || '';
                        },
                        maxRotation: 45,
                    },
                    grid: { color: '#e5e7eb' },
                },
                y: {
                    min: -0.5,
                    max: 6.5,
                    ticks: {
                        callback: function (value) {
                            return dayLabels[value] || '';
                        },
                        stepSize: 1,
                    },
                    grid: { color: '#e5e7eb' },
                },
            },
        },
    });
}

/*
 *  JustGage replacement — simple doughnut gauge.
 *  Templates call: new JustGage({id, value, min, max, title, label, …})
 *  We provide a compatible shim that renders a Chart.js doughnut.
 */
function JustGage(opts) {
    var value = opts.value || 0;
    var max = opts.max || 100;
    var min = opts.min || 0;
    var range = max - min;
    var pct = range > 0 ? ((value - min) / range) * 100 : 0;
    var remaining = 100 - pct;
    var title = opts.title || '';
    var label = opts.label || '';

    // Pick colour based on percentage
    var color;
    if (pct >= 80) color = SEV.green;
    else if (pct >= 50) color = SEV.medium;
    else if (pct >= 25) color = SEV.high;
    else color = SEV.critical;

    var id = '#' + opts.id;
    var canvas = _ensureCanvas(id);
    if (!canvas) return;

    var key = opts.id;
    _destroyChart(key);

    // Render value in the centre using a Chart.js plugin
    var centerTextPlugin = {
        id: 'centerText_' + key,
        afterDraw: function (chart) {
            var ctx = chart.ctx;
            var w = chart.width;
            var h = chart.height;
            ctx.save();
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            // Value
            ctx.font = 'bold 1.5rem Inter, system-ui, sans-serif';
            ctx.fillStyle = '#1f2937';
            ctx.fillText(value, w / 2, h / 2 - 8);
            // Label
            if (label) {
                ctx.font = '0.75rem Inter, system-ui, sans-serif';
                ctx.fillStyle = '#6b7280';
                ctx.fillText(label, w / 2, h / 2 + 14);
            }
            ctx.restore();
        },
    };

    var chart = new Chart(canvas.getContext('2d'), {
        type: 'doughnut',
        data: {
            labels: [title, ''],
            datasets: [{
                data: [pct, remaining],
                backgroundColor: [color, '#e5e7eb'],
                borderWidth: 0,
            }],
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            rotation: -90,
            circumference: 180,
            cutout: '75%',
            plugins: {
                legend: { display: false },
                tooltip: { enabled: false },
            },
        },
        plugins: [centerTextPlugin],
    });
    _chartInstances[key] = chart;
}
