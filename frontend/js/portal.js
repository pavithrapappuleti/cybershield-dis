/**
 * CyberShield User-Facing Web Portal Controller
 * Keeps internal security telemetry hidden from end users while interacting
 * with silently monitored backend endpoints.
 */

(() => {
  const loginCard = document.getElementById("user-login-card");
  const workspaceCard = document.getElementById("user-workspace-card");
  const loginForm = document.getElementById("portal-login-form");
  const loginFeedback = document.getElementById("portal-login-feedback");
  const userBadge = document.getElementById("portal-user-badge");
  const logoutBtn = document.getElementById("portal-logout-btn");
  const welcomeHeading = document.getElementById("portal-welcome-heading");
  const resourceOutput = document.getElementById("portal-resource-output");
  const serviceAlert = document.getElementById("portal-service-alert");
  const serviceAlertText = document.getElementById("portal-service-alert-text");

  function setSignedInUser(username) {
    const loggedIn = Boolean(username);
    loginCard.hidden = loggedIn;
    workspaceCard.hidden = !loggedIn;
    userBadge.hidden = !loggedIn;
    logoutBtn.hidden = !loggedIn;
    if (loggedIn) {
      userBadge.textContent = `Signed in: ${username}`;
      welcomeHeading.textContent = `Welcome, ${username}`;
    }
  }

  async function refreshSessionAndStatus() {
    try {
      const [sessRes, statusRes] = await Promise.all([
        fetch("/api/auth/session"),
        fetch("/api/portal/status"),
      ]);
      const sess = await sessRes.json();
      setSignedInUser(sess.authenticated ? sess.username : null);

      const st = await statusRes.json();
      if (!st.service_available) {
        serviceAlert.hidden = false;
        serviceAlertText.textContent = st.message;
      } else {
        serviceAlert.hidden = true;
      }
    } catch {
      // Fail silently on status poll
    }
  }

  // Educational Explorer Tabs
  document.querySelectorAll(".portal-tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      const target = tab.dataset.section;
      document.querySelectorAll(".portal-tab").forEach((t) => t.classList.toggle("active", t === tab));
      document.querySelectorAll(".portal-section").forEach((sec) => {
        const active = sec.id === `sec-${target}`;
        sec.hidden = !active;
        sec.classList.toggle("active", active);
      });
    });
  });

  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = document.getElementById("portal-username").value.trim();
    const password = document.getElementById("portal-password").value;

    loginFeedback.hidden = false;
    loginFeedback.textContent = "Verifying credentials...";

    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json();

      if (res.ok && data.authenticated) {
        loginFeedback.hidden = true;
        document.getElementById("portal-password").value = "";
        setSignedInUser(data.username);
      } else {
        // User sees only normal app error or generic lockout message
        loginFeedback.textContent = data.error || "Sign-in failed. Please try again.";
      }
    } catch {
      loginFeedback.textContent = "Unable to reach authentication service.";
    }
  });

  logoutBtn.addEventListener("click", async () => {
    await fetch("/api/auth/logout", { method: "POST" });
    resourceOutput.hidden = true;
    setSignedInUser(null);
  });

  document.getElementById("btn-fetch-portal-resources").addEventListener("click", async () => {
    resourceOutput.hidden = false;
    resourceOutput.textContent = "Loading active modules...";
    try {
      const res = await fetch("/api/records/public");
      const data = await res.json();
      if (!res.ok) {
        resourceOutput.textContent = data.error || "Unable to load modules right now.";
        return;
      }
      resourceOutput.innerHTML = data.modules
        .map((m) => `<div><strong>${m.name}</strong> — ${m.state}</div>`)
        .join("");
    } catch {
      resourceOutput.textContent = "Service temporarily unavailable.";
    }
  });

  document.getElementById("btn-probe-admin-diag").addEventListener("click", async () => {
    resourceOutput.hidden = false;
    try {
      const res = await fetch("/api/admin/debug-console");
      const data = await res.json();
      resourceOutput.textContent = data.error || "Access denied.";
    } catch {
      resourceOutput.textContent = "Access denied.";
    }
  });

  window.addEventListener("DOMContentLoaded", () => {
    refreshSessionAndStatus();
    setInterval(refreshSessionAndStatus, 5000);
  });
})();
