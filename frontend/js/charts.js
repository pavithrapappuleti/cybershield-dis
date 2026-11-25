/**
 * Chart.js Analytics & Telemetry Chart Manager
 */

const CyberCharts = (() => {
  const instances = {};

  function getOrCreate(canvasId, configFactory) {
    const canvas = document.getElementById(canvasId);
    if (!canvas || typeof Chart === "undefined") return null;
    if (instances[canvasId]) {
      instances[canvasId].destroy();
    }
    instances[canvasId] = new Chart(canvas, configFactory());
    return instances[canvasId];
  }

  const baseOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        labels: { color: "#9fb2d4", boxWidth: 12, font: { size: 11 } },
      },
    },
    scales: {
      x: {
        ticks: { color: "#6f84a8", font: { size: 11 } },
        grid: { color: "rgba(56, 189, 248, 0.08)" },
      },
      y: {
        beginAtZero: true,
        ticks: { color: "#6f84a8", font: { size: 11 } },
        grid: { color: "rgba(56, 189, 248, 0.08)" },
      },
    },
  };

  function renderDashboardCharts(chartsData) {
    const healthSeries = chartsData.system_health_history || [];
    getOrCreate("chart-health-trend", () => ({
      type: "line",
      data: {
        labels: healthSeries.map((h) =>
          h.recorded_at ? new Date(h.recorded_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : ""
        ),
        datasets: [
          {
            label: "Availability %",
            data: healthSeries.map((h) => h.availability_pct),
            borderColor: "#00d4ff",
            backgroundColor: "rgba(0, 212, 255, 0.14)",
            fill: true,
            tension: 0.3,
          },
          {
            label: "Avg Latency (ms)",
            data: healthSeries.map((h) => h.avg_response_ms),
            borderColor: "#8b5cf6",
            backgroundColor: "rgba(139, 92, 246, 0.1)",
            tension: 0.3,
          },
        ],
      },
      options: baseOptions,
    }));

    const daily = chartsData.daily_incident_trend || [];
    getOrCreate("chart-daily-trend", () => ({
      type: "bar",
      data: {
        labels: daily.map((d) => d.date.slice(5)),
        datasets: [
          {
            label: "Incidents",
            data: daily.map((d) => d.incidents),
            backgroundColor: "rgba(239, 68, 68, 0.7)",
            borderRadius: 6,
          },
          {
            label: "Security Events",
            data: daily.map((d) => d.events),
            backgroundColor: "rgba(59, 130, 246, 0.65)",
            borderRadius: 6,
          },
        ],
      },
      options: baseOptions,
    }));

    const sev = chartsData.severity_distribution || {};
    getOrCreate("chart-severity-dist", () => ({
      type: "doughnut",
      data: {
        labels: ["Low", "Medium", "High", "Critical"],
        datasets: [
          {
            data: [sev.Low || 0, sev.Medium || 0, sev.High || 0, sev.Critical || 0],
            backgroundColor: ["#10b981", "#3b82f6", "#f59e0b", "#ef4444"],
            borderColor: "#0c162e",
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { color: "#9fb2d4", padding: 14 } },
        },
      },
    }));
  }

  function renderReportCharts(reportData) {
    const common = reportData.common_event_types || [];
    getOrCreate("chart-report-events", () => ({
      type: "bar",
      data: {
        labels: common.map((item) => item.event_type),
        datasets: [
          {
            label: "Event Count",
            data: common.map((item) => item.count),
            backgroundColor: "rgba(0, 212, 255, 0.68)",
            borderRadius: 6,
          },
        ],
      },
      options: baseOptions,
    }));

    const res = reportData.incident_resolution_status || {};
    getOrCreate("chart-report-resolution", () => ({
      type: "doughnut",
      data: {
        labels: ["New", "Investigating", "Resolved", "False Positive"],
        datasets: [
          {
            data: [
              res.New || 0,
              res.Investigating || 0,
              res.Resolved || 0,
              res["False Positive"] || 0,
            ],
            backgroundColor: ["#00d4ff", "#f59e0b", "#10b981", "#64748b"],
            borderColor: "#0c162e",
            borderWidth: 2,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom", labels: { color: "#9fb2d4", padding: 12 } },
        },
      },
    }));

    const trends = reportData.event_trends || [];
    getOrCreate("chart-report-trends", () => ({
      type: "line",
      data: {
        labels: trends.map((t) => t.date.slice(5)),
        datasets: [
          {
            label: "Total Events",
            data: trends.map((t) => t.total_events),
            borderColor: "#3b82f6",
            tension: 0.3,
          },
          {
            label: "Threat Events",
            data: trends.map((t) => t.threat_events),
            borderColor: "#ef4444",
            tension: 0.3,
          },
        ],
      },
      options: baseOptions,
    }));
  }

  return { renderDashboardCharts, renderReportCharts };
})();
