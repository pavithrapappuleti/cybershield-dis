/**
 * CyberShield REST API Client
 */

const ApiClient = (() => {
  async function request(url, options = {}) {
    const config = {
      headers: {
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
      ...options,
    };

    const response = await fetch(url, config);
    const contentType = response.headers.get("content-type") || "";
    const data = contentType.includes("application/json")
      ? await response.json()
      : await response.text();

    if (!response.ok) {
      const msg = (data && data.error) || `Request failed with status ${response.status}`;
      throw new Error(msg);
    }
    return data;
  }

  return {
    getHealth: () => request("/api/health"),
    getDashboard: () => request("/api/dashboard"),
    getMonitoring: (refresh = false) =>
      request(`/api/monitoring${refresh ? "?refresh=true" : ""}`),
    getEvents: (threatsOnly = false) =>
      request(`/api/events?threats_only=${threatsOnly ? "true" : "false"}`),
    getRules: () => request("/api/rules"),
    updateRule: (id, payload) =>
      request(`/api/rules/${id}`, { method: "PATCH", body: JSON.stringify(payload) }),
    getIncidents: (params = {}) => {
      const qs = new URLSearchParams();
      Object.entries(params).forEach(([k, v]) => {
        if (v) qs.set(k, v);
      });
      const query = qs.toString();
      return request(`/api/incidents${query ? `?${query}` : ""}`);
    },
    getIncidentDetail: (id) => request(`/api/incidents/${id}`),
    updateIncidentStatus: (id, payload) =>
      request(`/api/incidents/${id}`, { method: "PATCH", body: JSON.stringify(payload) }),
    getBlockedSources: () => request("/api/blocked-sources"),
    unblockSource: (id, resolveIncident = false) =>
      request(`/api/blocked-sources/${id}/unblock`, {
        method: "POST",
        body: JSON.stringify({
          actor: "Admin Monitor",
          resolve_incident: resolveIncident,
        }),
      }),
    clearLoginAlerts: (sourceIp = null) =>
      request("/api/alerts/clear", {
        method: "POST",
        body: JSON.stringify({
          source_ip: sourceIp,
          resolve_login_incidents: true,
        }),
      }),
    approveBlock: (id) =>
      request(`/api/blocked-sources/${id}/approve`, {
        method: "POST",
        body: JSON.stringify({ actor: "SOC Administrator" }),
      }),
    getRecovery: () => request("/api/recovery"),
    triggerRecovery: (targetType = "auto") =>
      request("/api/recovery/trigger", {
        method: "POST",
        body: JSON.stringify({ target_type: targetType }),
      }),
    getRecoverySettings: () => request("/api/recovery/settings"),
    updateRecoverySettings: (payload) =>
      request("/api/recovery/settings", { method: "PATCH", body: JSON.stringify(payload) }),
    loginPortal: (username, password) =>
      request("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      }),
    getAdminSession: () => request("/api/admin/session"),
    adminLogin: (username, password) =>
      request("/api/admin/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      }),
    adminLogout: () => request("/api/admin/logout", { method: "POST" }),
    probeRestrictedEndpoint: () => request("/api/admin/debug-console"),
    getImmuneMemory: () => request("/api/immune-memory"),
    getReports: () => request("/api/reports"),
    simulateFailedLogins: (sourceIp, attempts) =>
      request("/api/simulation/failed-logins", {
        method: "POST",
        body: JSON.stringify({ source_ip: sourceIp, attempts }),
      }),
    simulateSuspiciousTraffic: (sourceIp, requestCount) =>
      request("/api/simulation/suspicious-traffic", {
        method: "POST",
        body: JSON.stringify({ source_ip: sourceIp, request_count: requestCount }),
      }),
    simulateRestrictedAccess: (sourceIp, probes) =>
      request("/api/simulation/restricted-access", {
        method: "POST",
        body: JSON.stringify({ source_ip: sourceIp, probes }),
      }),
    simulateServiceFailure: () =>
      request("/api/simulation/service-failure", { method: "POST", body: JSON.stringify({}) }),
    simulateDatabaseFailure: () =>
      request("/api/simulation/database-failure", { method: "POST", body: JSON.stringify({}) }),
    simulateExcessiveErrors: () =>
      request("/api/simulation/excessive-errors", { method: "POST", body: JSON.stringify({ error_count: 18 }) }),
    simulateServiceRecovery: () =>
      request("/api/simulation/service-recovery", { method: "POST", body: JSON.stringify({}) }),
    simulateNormalTraffic: () =>
      request("/api/simulation/normal-traffic", {
        method: "POST",
        body: JSON.stringify({ request_count: 6 }),
      }),
    resetBaseline: () =>
      request("/api/simulation/reset", { method: "POST", body: JSON.stringify({}) }),
  };
})();
