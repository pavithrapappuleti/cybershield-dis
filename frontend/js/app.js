/**
 * CyberShield Simplified Admin Monitor Controller
 * Clean, presentation-friendly view showing multiple wrong login alerts,
 * system warnings, active blocks, and autonomous self-healing.
 */

(() => {
  let currentTab = "monitor";
  let liveSyncInterval = null;
  let autoHealPollTimer = null;

  const loadingBar = document.getElementById("loading-bar");
  const statusPill = document.getElementById("global-status-pill");
  const statusText = document.getElementById("global-status-text");
  const alertBanner = document.getElementById("system-alert-banner");
  const alertBannerTitle = document.getElementById("alert-banner-title");
  const alertBannerDesc = document.getElementById("alert-banner-desc");
  const alertBannerActions = document.getElementById("alert-banner-actions");
  const toastRegion = document.getElementById("toast-region");
  const incidentModal = document.getElementById("incident-modal");
  const adminGate = document.getElementById("admin-auth-gate");
  const adminShell = document.getElementById("admin-app-shell");
  const adminLoginForm = document.getElementById("admin-login-form");
  const adminLoginError = document.getElementById("admin-login-error");

  function escapeHtml(val) {
    if (val === null || val === undefined) return "";
    return String(val)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function formatTime(isoString) {
    if (!isoString) return "—";
    const d = new Date(isoString);
    return Number.isNaN(d.getTime()) ? isoString : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  function severityBadge(sev) {
    const cls = (sev || "low").toLowerCase();
    return `<span class="badge badge-${cls}">${escapeHtml(sev)}</span>`;
  }

  function statusBadge(st) {
    const norm = (st || "new").toLowerCase().replace(/\s+/g, "");
    const map = {
      new: "badge-high",
      investigating: "badge-investigating",
      resolved: "badge-resolved",
      falsepositive: "badge-false",
    };
    return `<span class="badge ${map[norm] || "badge-high"}">${escapeHtml(st)}</span>`;
  }

  function friendlyEventName(ev) {
    const map = {
      failed_login_burst: "Wrong Password Attempt",
      normal_traffic: "Normal Sign-In / Traffic",
      restricted_endpoint_access: "Restricted Page Probe",
      suspicious_frequency: "High Traffic Burst",
      repeated_ip_requests: "Repeated Page Requests",
      service_failure: "API Service Crash",
      database_failure: "Database Connection Failure",
      excessive_errors: "Server Error Spike",
    };
    return map[ev.event_type] || ev.event_type;
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
    }, 5000);
  }

  function setLoading(isLoading) {
    loadingBar.hidden = !isLoading;
  }

  function switchTab(tabKey) {
    currentTab = tabKey;
    document.querySelectorAll(".portal-tab").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.tab === tabKey);
    });
    document.getElementById("tab-monitor").hidden = tabKey !== "monitor";
    document.getElementById("tab-demo").hidden = tabKey !== "demo";
  }

  document.querySelectorAll(".portal-tab").forEach((btn) => {
    btn.addEventListener("click", () => switchTab(btn.dataset.tab));
  });

  function renderAlertBanner(health, loginWarnings) {
    const st = health.overall_status || "Healthy";
    const norm = st.toLowerCase();
    statusPill.className = `status-pill status-${norm}`;
    statusText.textContent = `System: ${st}`;

    alertBanner.className = `alert-banner alert-${norm}`;
    alertBannerActions.innerHTML = "";

    const reasons = health.status_reasons || [];
    if (st === "Critical") {
      alertBannerTitle.textContent = "SYSTEM CRITICAL — Service Disruption Detected";
      const countdown = health.auto_heal && health.auto_heal.seconds_until_heal !== null
        ? ` Auto Self-Healing will recover in ~${health.auto_heal.seconds_until_heal}s.`
        : "";
      alertBannerDesc.textContent = (reasons[0] || "A service component has failed.") + countdown;

      const healBtn = document.createElement("button");
      healBtn.type = "button";
      healBtn.className = "btn btn-success btn-sm";
      healBtn.textContent = "Heal System Now";
      healBtn.addEventListener("click", triggerQuickHeal);
      alertBannerActions.appendChild(healBtn);
    } else if (st === "Warning") {
      alertBannerTitle.textContent =
        loginWarnings.length > 0
          ? "SYSTEM WARNING — Multiple Wrong Login Attempts Detected"
          : "SYSTEM WARNING — Security Alert Requires Attention";
      alertBannerDesc.textContent =
        reasons.join(" · ") || "Suspicious login or security activity detected.";

      if (loginWarnings.length > 0) {
        const clearBtn = document.createElement("button");
        clearBtn.type = "button";
        clearBtn.className = "btn btn-secondary btn-sm";
        clearBtn.textContent = "Clear Login Warning";
        clearBtn.addEventListener("click", () => clearWarnings());
        alertBannerActions.appendChild(clearBtn);
      }
    } else {
      alertBannerTitle.textContent = "System Healthy";
      alertBannerDesc.textContent =
        "No active threats or repeated wrong login attempts. Single login mistakes are monitored without raising false alarms.";
    }

    // Auto-refresh shortly after Autonomous Watchdog finishes healing
    const ah = health.auto_heal;
    if (ah && ah.enabled && ah.seconds_until_heal !== null && !autoHealPollTimer) {
      autoHealPollTimer = setTimeout(async () => {
        autoHealPollTimer = null;
        await refreshMonitor(true);
        showToast("CyberShield Self-Healing automatically restored system health.");
      }, Math.max(2200, (ah.seconds_until_heal + 1.5) * 1000));
    }
  }

  function renderWrongLogins(loginWarnings, blockedSources) {
    const tbody = document.getElementById("wrong-logins-body");
    const clearAllBtn = document.getElementById("btn-clear-warnings");

    // Combine active warnings + any recently released blocks or active blocks
    const rows = [];
    const seenIps = new Set();

    loginWarnings.forEach((w) => {
      seenIps.add(w.source_ip);
      rows.push({
        source_ip: w.source_ip,
        attempts: `${w.attempts} / ${w.threshold}`,
        badge: w.blocked
          ? '<span class="badge badge-critical">Blocked</span>'
          : '<span class="badge badge-high">System Warning</span>',
        reason: w.message,
        block_id: w.block_id,
        is_blocked: w.blocked,
        can_clear: true,
      });
    });

    blockedSources
      .filter((b) => (b.is_active || b.pending_approval) && !seenIps.has(b.source_ip))
      .forEach((b) => {
        rows.push({
          source_ip: b.source_ip,
          attempts: "Blocked",
          badge: '<span class="badge badge-critical">Blocked</span>',
          reason: b.reason,
          block_id: b.id,
          is_blocked: true,
          can_clear: false,
        });
      });

    clearAllBtn.hidden = loginWarnings.length === 0;

    if (!rows.length) {
      tbody.innerHTML =
        '<tr><td colspan="5" class="empty-state">No repeated wrong login warnings or blocked users right now.</td></tr>';
      return;
    }

    tbody.innerHTML = rows
      .map((r) => {
        let controlHtml = "";
        if (r.is_blocked && r.block_id) {
          controlHtml = `<button type="button" class="btn btn-primary btn-sm" data-unblock="${r.block_id}">Unblock</button>`;
        } else {
          controlHtml = `<button type="button" class="btn btn-secondary btn-sm" data-clear-ip="${escapeHtml(r.source_ip)}">Clear Warning</button>`;
        }
        return `
          <tr>
            <td class="mono">${escapeHtml(r.source_ip)}</td>
            <td><strong>${escapeHtml(r.attempts)}</strong></td>
            <td>${r.badge}</td>
            <td>${escapeHtml(r.reason)}</td>
            <td>${controlHtml}</td>
          </tr>`;
      })
      .join("");

    tbody.querySelectorAll("[data-unblock]").forEach((btn) => {
      btn.addEventListener("click", async () => {
        try {
          setLoading(true);
          const res = await ApiClient.unblockSource(Number(btn.dataset.unblock), true);
          showToast(res.message);
          await refreshMonitor();
        } catch (err) {
          showToast(err.message, "error");
        } finally {
          setLoading(false);
        }
      });
    });

    tbody.querySelectorAll("[data-clear-ip]").forEach((btn) => {
      btn.addEventListener("click", () => clearWarnings(btn.dataset.clearIp));
    });
  }

  function renderThreatAlerts(incidents) {
    const listEl = document.getElementById("alerts-list");
    const openCount = incidents.filter((i) => i.status === "New" || i.status === "Investigating").length;
    document.getElementById("incidents-count-chip").textContent = `${openCount} Active`;

    if (!incidents.length) {
      listEl.innerHTML = '<p class="empty-state">No security alerts recorded yet.</p>';
      return;
    }

    listEl.innerHTML = incidents
      .map((inc) => {
        const canResolve = inc.status === "New" || inc.status === "Investigating";
        return `
          <div class="stack-item simple-alert-item">
            <div class="simple-alert-body" data-inspect-inc="${inc.id}">
              <div class="stack-item-title">${escapeHtml(inc.title)}</div>
              <div class="stack-item-meta">${escapeHtml(inc.detection_reason)}</div>
              <div class="stack-item-meta"><strong>Response:</strong> ${escapeHtml(inc.response_action)}</div>
            </div>
            <div class="inline-controls">
              ${severityBadge(inc.severity)}
              ${statusBadge(inc.status)}
              ${canResolve ? `<button type="button" class="btn btn-secondary btn-sm" data-resolve-inc="${inc.id}">Resolve</button>` : ""}
            </div>
          </div>`;
      })
      .join("");

    listEl.querySelectorAll("[data-inspect-inc]").forEach((el) => {
      el.addEventListener("click", () => openIncidentModal(Number(el.dataset.inspectInc)));
    });

    listEl.querySelectorAll("[data-resolve-inc]").forEach((btn) => {
      btn.addEventListener("click", async (e) => {
        e.stopPropagation();
        try {
          setLoading(true);
          const res = await ApiClient.updateIncidentStatus(Number(btn.dataset.resolveInc), {
            status: "Resolved",
            notes: "Marked resolved from Admin Monitor.",
          });
          showToast(res.message);
          await refreshMonitor();
        } catch (err) {
          showToast(err.message, "error");
        } finally {
          setLoading(false);
        }
      });
    });
  }

  function renderRecoverySection(health, recoveries) {
    document.getElementById("rec-api-state").textContent = health.api_status;
    document.getElementById("rec-db-state").textContent = health.database_status;
    document.getElementById("rec-svc-state").textContent = health.service_status;

    const ah = health.auto_heal || {};
    const toggle = document.getElementById("toggle-auto-heal");
    const label = document.getElementById("auto-heal-label");
    toggle.checked = Boolean(ah.enabled);
    label.textContent = ah.enabled ? `Auto-Heal (${ah.delay_seconds}s)` : "Auto-Heal OFF";
    document.getElementById("kpi-autoheal-sub").textContent = ah.enabled
      ? `Auto-Heal: ON (${ah.delay_seconds}s)`
      : "Auto-Heal: Manual";

    const listEl = document.getElementById("recovery-list");
    if (!recoveries.length) {
      listEl.innerHTML = '<p class="empty-state">No recovery actions needed yet.</p>';
      return;
    }

    listEl.innerHTML = recoveries
      .map(
        (r) => `
        <div class="stack-item">
          <div>
            <div class="stack-item-title">${escapeHtml(r.action_taken)}</div>
            <div class="stack-item-meta">${escapeHtml(formatTime(r.created_at))} · ${escapeHtml(r.health_before)} &rarr; ${escapeHtml(r.health_after)}</div>
          </div>
          <span class="badge badge-resolved">${r.duration_ms} ms</span>
        </div>`
      )
      .join("");
  }

  function renderRecentActivity(activities) {
    const tbody = document.getElementById("activity-table-body");
    if (!activities.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No activity recorded yet.</td></tr>';
      return;
    }

    tbody.innerHTML = activities
      .map((ev) => {
        let outcome = '<span class="badge badge-low">Normal</span>';
        if (ev.is_threat) {
          outcome = '<span class="badge badge-critical">Blocked / Alert</span>';
        } else if (ev.event_type === "failed_login_burst") {
          outcome = '<span class="badge badge-high">Wrong Password</span>';
        }
        return `
          <tr>
            <td>${escapeHtml(formatTime(ev.created_at))}</td>
            <td class="mono">${escapeHtml(ev.source_ip)}</td>
            <td><strong>${escapeHtml(friendlyEventName(ev))}</strong></td>
            <td>${outcome}</td>
            <td>${escapeHtml(ev.payload_summary || ev.detection_reason)}</td>
          </tr>`;
      })
      .join("");
  }

  async function refreshMonitor(silent = false) {
    try {
      if (!silent) setLoading(true);
      const data = await ApiClient.getDashboard();
      const health = data.health || {};
      const warnings = data.login_warnings || health.login_warnings || [];

      renderAlertBanner(health, warnings);

      document.getElementById("kpi-health").textContent = data.system_status;
      document.getElementById("kpi-health-sub").textContent =
        `API: ${health.api_status} · DB: ${health.database_status}`;
      document.getElementById("kpi-wrong-logins").textContent = data.summary.recent_wrong_logins || 0;
      document.getElementById("kpi-wrong-logins-sub").textContent =
        warnings.length > 0
          ? `${warnings.length} source(s) flagged`
          : "Triggers warning at 2+, block at 5";
      document.getElementById("kpi-blocks").textContent = data.summary.active_simulated_blocks || 0;
      document.getElementById("kpi-blocks-sub").textContent =
        data.summary.active_simulated_blocks > 0 ? "Auto-blocking active" : "No users blocked";
      document.getElementById("kpi-recoveries").textContent = data.summary.total_recoveries || 0;

      renderWrongLogins(warnings, data.blocked_sources || []);
      renderThreatAlerts(data.recent_incidents || []);
      renderRecoverySection(health, data.recent_recoveries || []);
      renderRecentActivity(data.recent_activities || []);
    } catch (err) {
      if (!silent) showToast(err.message, "error");
    } finally {
      if (!silent) setLoading(false);
    }
  }

  async function clearWarnings(sourceIp = null) {
    try {
      setLoading(true);
      const res = await ApiClient.clearLoginAlerts(sourceIp);
      showToast(res.message);
      await refreshMonitor();
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      setLoading(false);
    }
  }

  async function triggerQuickHeal() {
    try {
      setLoading(true);
      const res = await ApiClient.triggerRecovery("auto");
      showToast(res.message);
      await refreshMonitor();
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      setLoading(false);
    }
  }

  async function openIncidentModal(incidentId) {
    try {
      setLoading(true);
      const res = await ApiClient.getIncidentDetail(incidentId);
      const inc = res.incident;

      document.getElementById("modal-inc-code").textContent = inc.incident_code;
      document.getElementById("modal-inc-title").textContent = inc.title;
      document.getElementById("modal-inc-summary").innerHTML = `
        <div class="modal-stat"><span class="kpi-label">Source IP</span><div class="mono">${escapeHtml(inc.source_ip)}</div></div>
        <div class="modal-stat"><span class="kpi-label">Severity</span><div>${severityBadge(inc.severity)}</div></div>
        <div class="modal-stat"><span class="kpi-label">Status</span><div>${statusBadge(inc.status)}</div></div>
      `;
      document.getElementById("modal-inc-reason").textContent = `Why it happened: ${inc.detection_reason}`;
      document.getElementById("modal-inc-response").textContent = `Action taken: ${inc.response_action}`;

      const timeline = document.getElementById("modal-inc-timeline");
      timeline.innerHTML = (inc.history || [])
        .map(
          (h) => `
          <li>
            <strong>${escapeHtml(h.event_stage)}:</strong> ${escapeHtml(h.action)}
            <div class="stack-item-meta">${escapeHtml(h.actor)} · ${escapeHtml(formatTime(h.timestamp))}</div>
          </li>`
        )
        .join("");

      if (!incidentModal.open) incidentModal.showModal();
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      setLoading(false);
    }
  }

  async function runSimulation(actionFn) {
    try {
      setLoading(true);
      const res = await actionFn();
      document.getElementById("sim-result-badge").textContent = res.message || "Completed";
      const steps = res.workflow_steps || [];
      document.getElementById("sim-timeline-container").innerHTML = steps
        .map(
          (s) => `
          <div class="timeline-step">
            <div class="timeline-step-stage">${escapeHtml(s.stage)}</div>
            <div>${escapeHtml(s.summary)}</div>
          </div>`
        )
        .join("");
      showToast(res.message);
      await refreshMonitor(true);
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      setLoading(false);
    }
  }

  document.getElementById("btn-clear-warnings").addEventListener("click", () => clearWarnings());
  document.getElementById("btn-heal-now").addEventListener("click", triggerQuickHeal);
  document.getElementById("toggle-auto-heal").addEventListener("change", async (e) => {
    try {
      const res = await ApiClient.updateRecoverySettings({ enabled: e.target.checked });
      showToast(res.message);
      await refreshMonitor(true);
    } catch (err) {
      showToast(err.message, "error");
    }
  });

  document.getElementById("btn-sim-failed-logins").addEventListener("click", () => {
    runSimulation(() => ApiClient.simulateFailedLogins("203.0.113.45", 6));
  });
  document.getElementById("btn-sim-api-failure").addEventListener("click", () => {
    runSimulation(() => ApiClient.simulateServiceFailure());
  });
  document.getElementById("btn-sim-db-failure").addEventListener("click", () => {
    runSimulation(() => ApiClient.simulateDatabaseFailure());
  });
  document.getElementById("btn-sim-normal").addEventListener("click", () => {
    runSimulation(() => ApiClient.simulateNormalTraffic());
  });

  document.getElementById("reset-demo-btn").addEventListener("click", async () => {
    try {
      setLoading(true);
      const res = await ApiClient.resetBaseline();
      showToast(res.message);
      await refreshMonitor();
    } catch (err) {
      showToast(err.message, "error");
    } finally {
      setLoading(false);
    }
  });

  function startLiveSync() {
    if (liveSyncInterval) clearInterval(liveSyncInterval);
    liveSyncInterval = setInterval(() => {
      const toggle = document.getElementById("toggle-live-sync");
      if (toggle && toggle.checked && !adminShell.hidden && !incidentModal.open) {
        refreshMonitor(true);
      }
    }, 3000);
  }

  function setAdminAuthenticated(authenticated) {
    adminGate.hidden = authenticated;
    adminShell.hidden = !authenticated;
    if (authenticated) {
      refreshMonitor();
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
      showToast("Signed in to CyberShield Admin.");
    } catch (err) {
      adminLoginError.textContent = err.message;
      adminLoginError.hidden = false;
    }
  });

  document.getElementById("admin-logout-btn").addEventListener("click", async () => {
    await ApiClient.adminLogout();
    setAdminAuthenticated(false);
  });

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

  window.addEventListener("DOMContentLoaded", async () => {
    try {
      const sess = await ApiClient.getAdminSession();
      setAdminAuthenticated(Boolean(sess.authenticated));
    } catch {
      setAdminAuthenticated(false);
    }
  });
})();
