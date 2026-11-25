/**
 * CyberShield SOC Frontend Controller
 * Connects all 10 dashboard pages to the Flask REST APIs.
 */

(() => {
  const PAGE_TITLES = {
    overview: "Security Overview",
    monitoring: "System Monitoring",
    detection: "Threat Detection",
    risk: "Risk Analysis",
    response: "Automated Threat Response",
    recovery: "Self-Recovery Engine",
    incidents: "Incident Management",
    immune: "Digital Immune Memory",
    simulation: "Security Simulation Lab",
    reports: "Reports & Analytics",
  };

  let currentPage = "overview";
  let currentModalIncidentId = null;

  const loadingBar = document.getElementById("loading-bar");
  const pageTitleEl = document.getElementById("page-title");
  const statusPill = document.getElementById("global-status-pill");
  const statusText = document.getElementById("global-status-text");
  const toastRegion = document.getElementById("toast-region");
  const incidentModal = document.getElementById("incident-modal");
  const adminGate = document.getElementById("admin-auth-gate");
  const adminShell = document.getElementById("admin-app-shell");
  const adminLoginForm = document.getElementById("admin-login-form");
  const adminLoginError = document.getElementById("admin-login-error");
  let autoHealPollTimer = null;
  let liveSyncInterval = null;

  function escapeHtml(val) {
    if (val === null || val === undefined) return "";
    return String(val)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function formatUtc(isoString) {
    if (!isoString) return "—";
    const d = new Date(isoString);
    return Number.isNaN(d.getTime()) ? isoString : d.toLocaleString();
  }

  function severityBadge(sev) {
    const cls = (sev || "low").toLowerCase();
    return `<span class="badge badge-${cls}">${escapeHtml(sev)}</span>`;
  }

  function statusBadge(st) {
    const norm = (st || "new").toLowerCase().replace(/\s+/g, "");
    const map = {
      new: "badge-new",
      investigating: "badge-investigating",
      resolved: "badge-resolved",
      falsepositive: "badge-false",
    };
    return `<span class="badge ${map[norm] || "badge-new"}">${escapeHtml(st)}</span>`;
  }

  function setLoading(isLoading) {
    loadingBar.hidden = !isLoading;
  }

  function showToast(message, variant = "success") {
    const toast = document.createElement("div");
    toast.className = `toast toast-${variant}`;
    const span = document.createElement("span");
    span.textContent = message;

    const closeBtn = document.createElement("button");
    closeBtn.type = "button";
    closeBtn.className = "icon-btn";
    closeBtn.setAttribute("aria-label", "Dismiss notification");
    closeBtn.textContent = "×";
    closeBtn.addEventListener("click", () => toast.remove());

    toast.append(span, closeBtn);
    toastRegion.appendChild(toast);
    setTimeout(() => {
      if (toast.isConnected) toast.remove();
    }, 5500);
  }

  function updateGlobalStatus(status, autoHeal = null) {
    const norm = (status || "Healthy").toLowerCase();
    statusPill.className = `status-pill status-${norm}`;
    statusText.textContent = `System: ${status}`;

    // If autonomous self-healing countdown is active, auto-refresh once healed
    if (autoHeal && autoHeal.enabled && autoHeal.seconds_until_heal !== null && !autoHealPollTimer) {
      autoHealPollTimer = setTimeout(async () => {
        autoHealPollTimer = null;
        await loadPage(currentPage);
        showToast("Autonomous Self-Healing Watchdog restored service state.");
      }, Math.max(2500, (autoHeal.seconds_until_heal + 1.5) * 1000));
    }
  }

  // Navigation & Mobile Drawer
  const sidebar = document.getElementById("sidebar");
  const sidebarBackdrop = document.getElementById("sidebar-backdrop");
  const openSidebarBtn = document.getElementById("open-sidebar-btn");
  const closeSidebarBtn = document.getElementById("close-sidebar-btn");

  function setDrawerOpen(open) {
    sidebar.classList.toggle("open", open);
    sidebarBackdrop.hidden = !open;
    openSidebarBtn.setAttribute("aria-expanded", String(open));
  }

  openSidebarBtn.addEventListener("click", () => setDrawerOpen(true));
  closeSidebarBtn.addEventListener("click", () => setDrawerOpen(false));
  sidebarBackdrop.addEventListener("click", () => setDrawerOpen(false));

  function navigateTo(pageKey) {
    currentPage = pageKey;
    pageTitleEl.textContent = PAGE_TITLES[pageKey] || "CyberShield";

    document.querySelectorAll(".nav-item").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.page === pageKey);
    });
    document.querySelectorAll(".page-view").forEach((sec) => {
      const match = sec.id === `page-${pageKey}`;
      sec.hidden = !match;
      sec.classList.toggle("active", match);
    });

    setDrawerOpen(false);
    loadPage(pageKey);
  }

  document.querySelectorAll(".nav-item").forEach((btn) => {
    btn.addEventListener("click", () => navigateTo(btn.dataset.page));
  });

  document.querySelectorAll("[data-goto]").forEach((btn) => {
    btn.addEventListener("click", () => navigateTo(btn.dataset.goto));
  });

  // PAGE 1: Security Overview
  async function loadOverview() {
    const data = await ApiClient.getDashboard();
    updateGlobalStatus(data.system_status);

    document.getElementById("kpi-health").textContent = data.system_status;
    document.getElementById("kpi-health-sub").textContent =
      `API: ${data.health.api_status} | DB: ${data.health.database_status}`;
    document.getElementById("kpi-total-events").textContent = data.summary.total_security_events;
    document.getElementById("kpi-threats").textContent = data.summary.detected_threats;
    document.getElementById("kpi-critical").textContent = data.summary.critical_incidents;
    document.getElementById("kpi-critical-sub").textContent =
      `${data.summary.open_incidents} open incident(s) total`;
    document.getElementById("kpi-blocks").textContent = data.summary.active_simulated_blocks;
    document.getElementById("kpi-availability").textContent = `${data.summary.service_availability_pct}%`;
    document.getElementById("kpi-latency-sub").textContent =
      `Avg response: ${data.health.avg_response_ms} ms`;

    CyberCharts.renderDashboardCharts(data.charts);

    const actBody = document.getElementById("overview-activities-body");
    if (!data.recent_activities.length) {
      actBody.innerHTML = `<tr><td colspan="5" class="empty-state">No recent telemetry events found.</td></tr>`;
    } else {
      actBody.innerHTML = data.recent_activities
        .map(
          (ev) => `
        <tr>
          <td>${escapeHtml(formatUtc(ev.created_at))}</td>
          <td class="mono">${escapeHtml(ev.source_ip)}</td>
          <td>${escapeHtml(ev.event_type)}</td>
          <td>${severityBadge(ev.severity)} <span class="mono">${ev.risk_score}</span></td>
          <td>${escapeHtml(ev.detection_reason)}</td>
        </tr>`
        )
        .join("");
    }

    const incList = document.getElementById("overview-incidents-list");
    if (!data.recent_incidents.length) {
      incList.innerHTML = `<p class="empty-state">No security incidents logged yet.</p>`;
    } else {
      incList.innerHTML = data.recent_incidents
        .map(
          (inc) => `
        <div class="stack-item" data-inspect-incident="${inc.id}">
          <div>
            <div class="stack-item-title">${escapeHtml(inc.incident_code)} — ${escapeHtml(inc.title)}</div>
            <div class="stack-item-meta">${escapeHtml(inc.source_ip)} · ${escapeHtml(inc.response_action)}</div>
          </div>
          <div class="inline-controls">
            ${severityBadge(inc.severity)}
            ${statusBadge(inc.status)}
          </div>
        </div>`
        )
        .join("");
      incList.querySelectorAll("[data-inspect-incident]").forEach((el) => {
        el.addEventListener("click", () => openIncidentModal(Number(el.dataset.inspectIncident)));
      });
    }
  }

  // PAGE 2: System Monitoring
  async function loadMonitoring(refresh = false) {
    const data = await ApiClient.getMonitoring(refresh);
    const h = data.health;
    updateGlobalStatus(h.overall_status);

    const real = h.real_metrics;
    document.getElementById("real-metrics-list").innerHTML = `
      <div><dt>Flask Process</dt><dd>${escapeHtml(real.flask_app_status)}</dd></div>
      <div><dt>Process Uptime</dt><dd>${real.uptime_seconds} s</dd></div>
      <div><dt>Real HTTP Requests</dt><dd>${real.real_request_count}</dd></div>
      <div><dt>Real HTTP Errors (4xx/5xx)</dt><dd>${real.real_error_count}</dd></div>
      <div><dt>SQLite Reachable</dt><dd>${real.sqlite_reachable ? "Yes (SELECT 1 OK)" : "Failed"}</dd></div>
      <div><dt>SQLite Ping Latency</dt><dd>${real.sqlite_ping_ms} ms</dd></div>
    `;

    const sim = h.simulated_state;
    document.getElementById("simulated-metrics-list").innerHTML = `
      <div><dt>Simulated API State</dt><dd>${escapeHtml(sim.api_status)}</dd></div>
      <div><dt>Simulated DB Pool State</dt><dd>${escapeHtml(sim.database_status)}</dd></div>
      <div><dt>Simulated Worker Service</dt><dd>${escapeHtml(sim.service_status)}</dd></div>
      <div><dt>Simulated Availability</dt><dd>${h.availability_pct}%</dd></div>
      <div><dt>Last State Change</dt><dd class="mono">${escapeHtml(formatUtc(sim.last_changed_at))}</dd></div>
      <div><dt>Fault Note</dt><dd>${escapeHtml(sim.failure_reason || "None — Healthy")}</dd></div>
    `;

    const logBody = document.getElementById("monitoring-log-body");
    const logs = data.monitoring_events || [];
    if (!logs.length) {
      logBody.innerHTML = `<tr><td colspan="6" class="empty-state">No monitoring log events recorded yet.</td></tr>`;
    } else {
      logBody.innerHTML = logs
        .map(
          (log) => `
        <tr>
          <td>${escapeHtml(formatUtc(log.timestamp))}</td>
          <td>${escapeHtml(log.category)}</td>
          <td>${severityBadge(log.level === "CRITICAL" || log.level === "ERROR" ? "Critical" : log.level === "WARNING" ? "High" : "Low")}</td>
          <td>${escapeHtml(log.source)}</td>
          <td>${log.is_simulated ? '<span class="chip chip-purple">Simulated</span>' : '<span class="chip">Real Flask</span>'}</td>
          <td>${escapeHtml(log.message)}</td>
        </tr>`
        )
        .join("");
    }
  }

  document.getElementById("manual-monitor-refresh-btn").addEventListener("click", async () => {
    try {
      setLoading(true);
      await loadMonitoring(true);
      showToast("Manual health snapshot recorded to SQLite.");
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      setLoading(false);
    }
  });

  // PAGE 3: Threat Detection
  async function loadDetection() {
    const threatsOnly = document.getElementById("events-threats-only").checked;
    const [rulesRes, eventsRes] = await Promise.all([
      ApiClient.getRules(),
      ApiClient.getEvents(threatsOnly),
    ]);

    const rulesBody = document.getElementById("rules-table-body");
    rulesBody.innerHTML = rulesRes.rules
      .map(
        (r) => `
      <tr data-rule-id="${r.id}">
        <td>
          <strong>${escapeHtml(r.name)}</strong>
          <div class="stack-item-meta">${escapeHtml(r.description)}</div>
        </td>
        <td class="mono">${escapeHtml(r.event_type)}</td>
        <td><input type="number" class="inline-input rule-threshold" value="${r.threshold_count}" min="1" max="1000" aria-label="Threshold for ${escapeHtml(r.name)}"></td>
        <td><input type="number" class="inline-input rule-window" value="${r.window_seconds}" min="10" max="86400" aria-label="Window for ${escapeHtml(r.name)}"></td>
        <td><input type="checkbox" class="rule-autoblock" ${r.auto_block_enabled ? "checked" : ""} aria-label="Auto block for ${escapeHtml(r.name)}"></td>
        <td><input type="checkbox" class="rule-approval" ${r.requires_human_approval ? "checked" : ""} aria-label="Require human approval for ${escapeHtml(r.name)}"></td>
        <td><button type="button" class="btn btn-primary btn-sm save-rule-btn">Save</button></td>
      </tr>`
      )
      .join("");

    rulesBody.querySelectorAll(".save-rule-btn").forEach((btn) => {
      btn.addEventListener("click", async () => {
        const row = btn.closest("tr");
        const ruleId = Number(row.dataset.ruleId);
        const payload = {
          threshold_count: Number(row.querySelector(".rule-threshold").value),
          window_seconds: Number(row.querySelector(".rule-window").value),
          auto_block_enabled: row.querySelector(".rule-autoblock").checked,
          requires_human_approval: row.querySelector(".rule-approval").checked,
        };
        try {
          const res = await ApiClient.updateRule(ruleId, payload);
          showToast(res.message);
        } catch (err) {
          showToast(err.message, "error");
        }
      });
    });

    const eventsBody = document.getElementById("events-table-body");
    if (!eventsRes.events.length) {
      eventsBody.innerHTML = `<tr><td colspan="8" class="empty-state">No matching security events recorded.</td></tr>`;
    } else {
      eventsBody.innerHTML = eventsRes.events
        .map(
          (ev) => `
        <tr>
          <td>${escapeHtml(formatUtc(ev.created_at))}</td>
          <td class="mono">${escapeHtml(ev.source_ip)}</td>
          <td class="mono">${escapeHtml(ev.event_type)}</td>
          <td class="mono">${escapeHtml(ev.endpoint)}</td>
          <td class="mono">${ev.risk_score}/100</td>
          <td>${severityBadge(ev.severity)}</td>
          <td>${ev.is_threat ? '<span class="badge badge-critical">Threat</span>' : '<span class="badge badge-low">Benign</span>'}</td>
          <td>${escapeHtml(ev.detection_reason)}</td>
        </tr>`
        )
        .join("");
    }
  }

  document.getElementById("events-threats-only").addEventListener("change", () => {
    loadDetection().catch((e) => showToast(e.message, "error"));
  });

  // PAGE 4: Risk Analysis
  function renderRiskDetail(inc) {
    const badge = document.getElementById("risk-selected-badge");
    badge.className = `badge badge-${inc.severity.toLowerCase()}`;
    badge.textContent = `${inc.severity} (${inc.risk_score}/100)`;

    const bd = inc.risk_breakdown || {};
    const factors = [
      { label: "Failed Login Volume", val: bd.failed_login_factor || 0, max: 30 },
      { label: "Request Frequency", val: bd.request_frequency_factor || 0, max: 25 },
      { label: "Event Repetition", val: bd.repetition_factor || 0, max: 20 },
      { label: "Activity Class Weight", val: bd.activity_type_factor || 0, max: 25 },
      { label: "Immune Memory Boost", val: bd.immune_memory_boost || 0, max: 15 },
    ];

    document.getElementById("risk-detail-panel").innerHTML = `
      <div class="risk-score-banner">
        <div>
          <div class="stack-item-meta">${escapeHtml(inc.incident_code)} · ${escapeHtml(inc.source_ip)}</div>
          <strong>${escapeHtml(inc.title)}</strong>
        </div>
        <div class="risk-score-big">${inc.risk_score}<span class="stack-item-meta">/100</span></div>
      </div>
      <div class="stack-list">
        ${factors
          .map((f) => {
            const pct = Math.min(100, Math.round((f.val / f.max) * 100));
            return `
            <div class="factor-row">
              <span>${escapeHtml(f.label)}</span>
              <div class="factor-track"><div class="factor-fill" style="--pct:${pct}"></div></div>
              <span class="mono">+${f.val}/${f.max}</span>
            </div>`;
          })
          .join("")}
      </div>
      <div class="detail-box"><strong>Detection Basis:</strong> ${escapeHtml(inc.detection_reason)}</div>
      <div class="detail-box"><strong>Recommended Response:</strong> ${escapeHtml(inc.recommended_response)}</div>
    `;
  }

  async function loadRiskAnalysis() {
    const res = await ApiClient.getIncidents();
    const listEl = document.getElementById("risk-incident-selector");
    if (!res.incidents.length) {
      listEl.innerHTML = `<p class="empty-state">No incidents available for risk inspection.</p>`;
      return;
    }

    listEl.innerHTML = res.incidents
      .map(
        (inc) => `
      <div class="stack-item" data-risk-id="${inc.id}">
        <div>
          <div class="stack-item-title">${escapeHtml(inc.incident_code)} — ${escapeHtml(inc.event_type)}</div>
          <div class="stack-item-meta">${escapeHtml(inc.source_ip)} · ${escapeHtml(formatUtc(inc.created_at))}</div>
        </div>
        <div>${severityBadge(inc.severity)} <span class="mono">${inc.risk_score}</span></div>
      </div>`
      )
      .join("");

    listEl.querySelectorAll("[data-risk-id]").forEach((el) => {
      el.addEventListener("click", () => {
        const match = res.incidents.find((i) => i.id === Number(el.dataset.riskId));
        if (match) renderRiskDetail(match);
      });
    });

    renderRiskDetail(res.incidents[0]);
  }

  // PAGE 5: Automated Response
  async function loadResponse() {
    const res = await ApiClient.getBlockedSources();
    document.getElementById("blocks-summary-chip").textContent =
      `${res.active_count} Active · ${res.pending_count} Pending Approval`;

    const tbody = document.getElementById("blocked-sources-body");
    if (!res.blocked_sources.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="empty-state">No simulated IP blocks recorded yet. Trigger a threat simulation to observe automated containment.</td></tr>`;
      return;
    }

    tbody.innerHTML = res.blocked_sources
      .map((b) => {
        let stateBadge = `<span class="badge badge-resolved">Released</span>`;
        if (b.pending_approval) {
          stateBadge = `<span class="badge badge-high">Pending Approval</span>`;
        } else if (b.is_active) {
          stateBadge = `<span class="badge badge-critical">Active Block</span>`;
        }

        const controls = [];
        if (b.pending_approval) {
          controls.push(`<button type="button" class="btn btn-primary btn-sm" data-approve-block="${b.id}">Approve Block</button>`);
        }
        if (b.is_active || b.pending_approval) {
          controls.push(`<button type="button" class="btn btn-secondary btn-sm" data-unblock="${b.id}">Manual Unblock</button>`);
        }

        return `
        <tr>
          <td class="mono">${escapeHtml(b.source_ip)}</td>
          <td>${stateBadge}</td>
          <td>${severityBadge(b.severity)} <span class="mono">${b.risk_score}</span></td>
          <td>${escapeHtml(b.approval_mode)}</td>
          <td>${escapeHtml(b.reason)}</td>
          <td>${escapeHtml(formatUtc(b.blocked_at))}</td>
          <td>${controls.length ? controls.join(" ") : `<span class="stack-item-meta">Unblocked by ${escapeHtml(b.unblocked_by || "System")}</span>`}</td>
        </tr>`;
      })
      .join("");

    tbody.querySelectorAll("[data-unblock]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          const r = await ApiClient.unblockSource(Number(btn.dataset.unblock));
          showToast(r.message);
          await loadResponse();
          await refreshTopStatus();
        } catch (err) {
          showToast(err.message, "error");
        }
      });
    });

    tbody.querySelectorAll("[data-approve-block]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          const r = await ApiClient.approveBlock(Number(btn.dataset.approveBlock));
          showToast(r.message);
          await loadResponse();
          await refreshTopStatus();
        } catch (err) {
          showToast(err.message, "error");
        }
      });
    });
  }

  // PAGE 6: Self-Recovery
  async function loadRecovery() {
    const res = await ApiClient.getRecovery();
    const h = res.current_health;
    updateGlobalStatus(h.overall_status, h.auto_heal);

    const toggleEl = document.getElementById("toggle-auto-heal");
    const labelEl = document.getElementById("auto-heal-status-label");
    if (toggleEl && h.auto_heal) {
      toggleEl.checked = Boolean(h.auto_heal.enabled);
      labelEl.textContent = h.auto_heal.enabled
        ? `Autonomous Watchdog: ON (${h.auto_heal.delay_seconds}s)`
        : "Autonomous Watchdog: OFF (Manual Only)";
    }

    document.getElementById("rec-api-state").textContent = h.api_status;
    document.getElementById("rec-db-state").textContent = h.database_status;
    document.getElementById("rec-svc-state").textContent = h.service_status;
    document.getElementById("rec-avg-ms").textContent = `${res.stats.avg_duration_ms} ms`;

    const tbody = document.getElementById("recovery-history-body");
    if (!res.recovery_actions.length) {
      tbody.innerHTML = `<tr><td colspan="6" class="empty-state">No recovery actions executed yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = res.recovery_actions
      .map(
        (r) => `
      <tr>
        <td>${escapeHtml(formatUtc(r.failure_detected_at))}</td>
        <td class="mono">${escapeHtml(r.failure_type)}</td>
        <td>${escapeHtml(r.action_taken)}</td>
        <td>${r.status === "Completed" ? '<span class="badge badge-resolved">Completed</span>' : '<span class="badge badge-critical">Failed</span>'}</td>
        <td class="mono">${r.duration_ms} ms</td>
        <td>${escapeHtml(r.health_before)} &rarr; <strong>${escapeHtml(r.health_after)}</strong></td>
      </tr>`
      )
      .join("");
  }

  document.querySelectorAll("[data-recover]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      try {
        setLoading(true);
        const res = await ApiClient.triggerRecovery(btn.dataset.recover);
        showToast(res.message);
        await loadRecovery();
      } catch (err) {
        showToast(err.message, "error");
      } finally {
        setLoading(false);
      }
    });
  });

  // PAGE 7: Incident Management & Modal
  async function loadIncidents() {
    const params = {
      search: document.getElementById("inc-search").value.trim(),
      severity: document.getElementById("inc-severity").value,
      status: document.getElementById("inc-status").value,
      date_from: document.getElementById("inc-date-from").value,
      date_to: document.getElementById("inc-date-to").value,
    };
    const res = await ApiClient.getIncidents(params);
    document.getElementById("incidents-count-chip").textContent = `${res.count} Incident(s)`;

    const tbody = document.getElementById("incidents-table-body");
    if (!res.incidents.length) {
      tbody.innerHTML = `<tr><td colspan="8" class="empty-state">No incidents match the selected filters.</td></tr>`;
      return;
    }

    tbody.innerHTML = res.incidents
      .map(
        (inc) => `
      <tr>
        <td class="mono">${escapeHtml(inc.incident_code)}</td>
        <td>${escapeHtml(inc.title)}</td>
        <td class="mono">${escapeHtml(inc.source_ip)}</td>
        <td>${severityBadge(inc.severity)}</td>
        <td class="mono">${inc.risk_score}/100</td>
        <td>${statusBadge(inc.status)}</td>
        <td>${escapeHtml(formatUtc(inc.created_at))}</td>
        <td><button type="button" class="btn btn-secondary btn-sm" data-open-inc="${inc.id}">Inspect</button></td>
      </tr>`
      )
      .join("");

    tbody.querySelectorAll("[data-open-inc]").forEach((btn) => {
      btn.addEventListener("click", () => openIncidentModal(Number(btn.dataset.openInc)));
    });
  }

  async function openIncidentModal(incidentId) {
    try {
      setLoading(true);
      const res = await ApiClient.getIncidentDetail(incidentId);
      const inc = res.incident;
      currentModalIncidentId = inc.id;

      document.getElementById("modal-inc-code").textContent = inc.incident_code;
      document.getElementById("modal-inc-title").textContent = inc.title;
      document.getElementById("modal-inc-summary").innerHTML = `
        <div class="modal-stat"><span class="kpi-label">Source IP</span><div class="mono">${escapeHtml(inc.source_ip)}</div></div>
        <div class="modal-stat"><span class="kpi-label">Severity</span><div>${severityBadge(inc.severity)}</div></div>
        <div class="modal-stat"><span class="kpi-label">Risk Score</span><div class="mono">${inc.risk_score}/100</div></div>
        <div class="modal-stat"><span class="kpi-label">Status</span><div>${statusBadge(inc.status)}</div></div>
      `;
      document.getElementById("modal-inc-reason").textContent = `Detection Reason: ${inc.detection_reason}`;
      document.getElementById("modal-inc-response").textContent = `Response Action: ${inc.response_action}`;
      document.getElementById("modal-status-select").value = inc.status;
      document.getElementById("modal-status-notes").value = "";

      const timeline = document.getElementById("modal-inc-timeline");
      timeline.innerHTML = (inc.history || [])
        .map(
          (h) => `
        <li>
          <strong>[${escapeHtml(h.event_stage)}]</strong> ${escapeHtml(h.action)}
          <div class="stack-item-meta">${escapeHtml(h.actor)} · ${escapeHtml(formatUtc(h.timestamp))}</div>
          ${h.notes ? `<div>${escapeHtml(h.notes)}</div>` : ""}
        </li>`
        )
        .join("");

      if (!incidentModal.open) {
        incidentModal.showModal();
      }
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      setLoading(false);
    }
  }

  document.getElementById("modal-status-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    if (!currentModalIncidentId) return;
    const status = document.getElementById("modal-status-select").value;
    const notes = document.getElementById("modal-status-notes").value.trim();
    try {
      const res = await ApiClient.updateIncidentStatus(currentModalIncidentId, { status, notes });
      showToast(res.message);
      await openIncidentModal(currentModalIncidentId);
      await loadPage(currentPage);
    } catch (err) {
      showToast(err.message, "error");
    }
  });

  document.getElementById("incident-filter-form").addEventListener("submit", (e) => {
    e.preventDefault();
    loadIncidents().catch((err) => showToast(err.message, "error"));
  });

  document.getElementById("inc-clear-filters").addEventListener("click", () => {
    document.getElementById("inc-search").value = "";
    document.getElementById("inc-severity").value = "";
    document.getElementById("inc-status").value = "";
    document.getElementById("inc-date-from").value = "";
    document.getElementById("inc-date-to").value = "";
    loadIncidents().catch((err) => showToast(err.message, "error"));
  });

  // PAGE 8: Digital Immune Memory
  async function loadImmuneMemory() {
    const res = await ApiClient.getImmuneMemory();
    document.getElementById("immune-total-sigs").textContent = res.total_cataloged_signatures;
    document.getElementById("immune-recurring-count").textContent = res.recurring_patterns_count;

    const tbody = document.getElementById("immune-patterns-body");
    if (!res.patterns.length) {
      tbody.innerHTML = `<tr><td colspan="7" class="empty-state">No historical patterns cataloged yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = res.patterns
      .map(
        (p) => `
      <tr>
        <td class="mono">${escapeHtml(p.immune_signature)}</td>
        <td class="mono">${escapeHtml(p.event_type)}</td>
        <td>${p.incident_count}</td>
        <td>${p.total_occurrences}</td>
        <td>${severityBadge(p.highest_severity)}</td>
        <td>${p.adaptive_boost > 0 ? `<span class="chip">+${p.adaptive_boost} Weight</span>` : '<span class="stack-item-meta">Baseline</span>'}</td>
        <td>${escapeHtml((p.previous_responses || []).join(" | ") || "Logged")}</td>
      </tr>`
      )
      .join("");
  }

  // PAGE 9: Simulation Lab
  function renderSimulationTimeline(res) {
    if (res.health) updateGlobalStatus(res.health.overall_status, res.health.auto_heal);
    if (res.health_after) updateGlobalStatus(res.health_after.overall_status, res.health_after.auto_heal);

    document.getElementById("sim-result-badge").textContent = res.message || "Simulation Completed";
    const container = document.getElementById("sim-timeline-container");
    const steps = res.workflow_steps || [];
    container.innerHTML = steps
      .map(
        (s) => `
      <div class="timeline-step">
        <div class="timeline-step-stage">${escapeHtml(s.stage)}</div>
        <div>${escapeHtml(s.summary)}</div>
      </div>`
      )
      .join("");
  }

  async function runSimulation(actionFn) {
    try {
      setLoading(true);
      const res = await actionFn();
      renderSimulationTimeline(res);
      showToast(res.message);
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      setLoading(false);
    }
  }

  document.getElementById("btn-sim-failed-logins").addEventListener("click", () => {
    const ip = document.getElementById("sim-login-ip").value.trim();
    const attempts = Number(document.getElementById("sim-login-attempts").value);
    runSimulation(() => ApiClient.simulateFailedLogins(ip, attempts));
  });

  document.getElementById("btn-sim-suspicious-traffic").addEventListener("click", () => {
    const ip = document.getElementById("sim-traffic-ip").value.trim();
    const count = Number(document.getElementById("sim-traffic-count").value);
    runSimulation(() => ApiClient.simulateSuspiciousTraffic(ip, count));
  });

  document.getElementById("btn-sim-restricted").addEventListener("click", () => {
    const ip = document.getElementById("sim-probe-ip").value.trim();
    const probes = Number(document.getElementById("sim-probe-count").value);
    runSimulation(() => ApiClient.simulateRestrictedAccess(ip, probes));
  });

  document.getElementById("btn-sim-api-failure").addEventListener("click", () => {
    runSimulation(() => ApiClient.simulateServiceFailure());
  });

  document.getElementById("btn-sim-db-failure").addEventListener("click", () => {
    runSimulation(() => ApiClient.simulateDatabaseFailure());
  });

  document.getElementById("btn-sim-excessive-errors").addEventListener("click", () => {
    runSimulation(() => ApiClient.simulateExcessiveErrors());
  });

  document.getElementById("btn-sim-recovery").addEventListener("click", () => {
    runSimulation(() => ApiClient.simulateServiceRecovery());
  });

  document.getElementById("btn-sim-normal").addEventListener("click", () => {
    runSimulation(() => ApiClient.simulateNormalTraffic());
  });

  // PAGE 10: Reports
  async function loadReports() {
    const data = await ApiClient.getReports();
    document.getElementById("rep-total-events").textContent = data.totals.total_events;
    document.getElementById("rep-total-incidents").textContent = data.totals.total_incidents;
    document.getElementById("rep-rec-rate").textContent = `${data.recovery_statistics.success_rate_pct}%`;
    document.getElementById("rep-rec-avg").textContent = `${data.recovery_statistics.avg_duration_ms} ms`;
    CyberCharts.renderReportCharts(data);
  }

  async function refreshTopStatus() {
    const healthRes = await ApiClient.getHealth();
    updateGlobalStatus(healthRes.status, healthRes.health && healthRes.health.auto_heal);
  }

  document.getElementById("toggle-auto-heal").addEventListener("change", async (e) => {
    try {
      const res = await ApiClient.updateRecoverySettings({ enabled: e.target.checked });
      showToast(res.message);
      await loadRecovery();
    } catch (err) {
      showToast(err.message, "error");
    }
  });

  async function loadPage(pageKey, silent = false) {
    try {
      if (!silent) setLoading(true);
      await refreshTopStatus();
      if (pageKey === "overview") await loadOverview();
      else if (pageKey === "monitoring") await loadMonitoring(false);
      else if (pageKey === "detection") await loadDetection();
      else if (pageKey === "risk") await loadRiskAnalysis();
      else if (pageKey === "response") await loadResponse();
      else if (pageKey === "recovery") await loadRecovery();
      else if (pageKey === "incidents") await loadIncidents();
      else if (pageKey === "immune") await loadImmuneMemory();
      else if (pageKey === "reports") await loadReports();
    } catch (err) {
      if (!silent) showToast(err.message, "error");
    } finally {
      if (!silent) setLoading(false);
    }
  }

  function startLiveSync() {
    if (liveSyncInterval) clearInterval(liveSyncInterval);
    liveSyncInterval = setInterval(() => {
      const toggle = document.getElementById("toggle-live-sync");
      if (toggle && toggle.checked && !adminShell.hidden && !incidentModal.open) {
        loadPage(currentPage, true);
      }
    }, 5000);
  }

  function setAdminAuthenticated(authenticated) {
    adminGate.hidden = authenticated;
    adminShell.hidden = !authenticated;
    if (authenticated) {
      loadPage(currentPage);
      startLiveSync();
    } else if (liveSyncInterval) {
      clearInterval(liveSyncInterval);
      liveSyncInterval = null;
    }
  }

  adminLoginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    adminLoginError.hidden = true;
    const username = document.getElementById("admin-username").value.trim();
    const password = document.getElementById("admin-password").value;
    try {
      await ApiClient.adminLogin(username, password);
      document.getElementById("admin-password").value = "";
      setAdminAuthenticated(true);
      showToast("Signed in to CyberShield Admin SOC.");
    } catch (err) {
      adminLoginError.textContent = err.message;
      adminLoginError.hidden = false;
    }
  });

  document.getElementById("admin-logout-btn").addEventListener("click", async () => {
    await ApiClient.adminLogout();
    setAdminAuthenticated(false);
  });

  document.getElementById("refresh-current-btn").addEventListener("click", () => {
    loadPage(currentPage);
  });

  document.getElementById("reset-demo-btn").addEventListener("click", async () => {
    try {
      setLoading(true);
      const res = await ApiClient.resetBaseline();
      showToast(res.message);
      await loadPage(currentPage);
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      setLoading(false);
    }
  });

  // Progressive enhancement fallback for <dialog closedby="any">
  if (!("closedBy" in HTMLDialogElement.prototype) && incidentModal) {
    const isOutside = (e, dlg) => {
      const r = dlg.getBoundingClientRect();
      return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
    };
    let pressedOutside = false;
    incidentModal.addEventListener("pointerdown", (e) => {
      pressedOutside = isOutside(e, incidentModal);
    });
    incidentModal.addEventListener("pointerup", (e) => {
      if (pressedOutside && isOutside(e, incidentModal)) incidentModal.close();
    });
  }

  // Initial session check on DOM ready
  window.addEventListener("DOMContentLoaded", async () => {
    try {
      const sess = await ApiClient.getAdminSession();
      setAdminAuthenticated(Boolean(sess.authenticated));
    } catch {
      setAdminAuthenticated(false);
    }
  });
})();
