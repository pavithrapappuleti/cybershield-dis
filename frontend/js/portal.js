
/**
 * CyberShield User-Facing Web Portal Controller
 *
 * Supports:
 * 1. Local Flask backend
 * 2. Vercel frontend + Render backend
 * 3. Render-hosted frontend/backend
 *
 * Keeps internal security telemetry hidden from end users.
 */

(() => {
  "use strict";

  const PORTAL_TOKEN_KEY = "cybershield_portal_token";

  // --------------------------------------------------
  // DOM ELEMENTS
  // --------------------------------------------------

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

  // --------------------------------------------------
  // API CONFIGURATION
  // --------------------------------------------------

  function resolveUrl(path) {
    const config = window.CYBERSHIELD_CONFIG;

    // Use the shared configuration when available.
    // Important: Do not use || with API_BASE_URL because
    // an empty string is valid for localhost.

    if (config && typeof config.buildUrl === "function") {
      return config.buildUrl(path);
    }

    // Fallback configuration.
    const hostname = window.location.hostname;

    const isLocalhost =
      hostname === "localhost" ||
      hostname === "127.0.0.1";

    const isRender =
      hostname.endsWith(".onrender.com");

    if (isLocalhost || isRender) {
      return path;
    }

    // Vercel frontend uses the deployed Render backend.
    return `https://cybershield-dis-1.onrender.com${path}`;
  }

  // --------------------------------------------------
  // TOKEN MANAGEMENT
  // --------------------------------------------------

  function getPortalToken() {
    try {
      return window.sessionStorage.getItem(PORTAL_TOKEN_KEY);
    } catch (error) {
      console.error("Unable to read portal token:", error);
      return null;
    }
  }

  function setPortalToken(token) {
    try {
      if (token) {
        window.sessionStorage.setItem(PORTAL_TOKEN_KEY, token);
      } else {
        window.sessionStorage.removeItem(PORTAL_TOKEN_KEY);
      }
    } catch (error) {
      console.error("Unable to update portal token:", error);
    }
  }

  // --------------------------------------------------
  // API REQUEST HANDLER
  // --------------------------------------------------

  async function portalFetch(path, options = {}) {
    const token = getPortalToken();

    const headers = {
      ...(options.headers || {}),
    };

    if (token) {
      headers.Authorization = `Bearer ${token}`;
    }

    const url = resolveUrl(path);

    return fetch(url, {
      ...options,
      credentials: "include",
      headers,
    });
  }

  // --------------------------------------------------
  // LOGIN UI MANAGEMENT
  // --------------------------------------------------

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

  // --------------------------------------------------
  // SESSION AND SERVICE STATUS
  // --------------------------------------------------

  async function refreshSessionAndStatus() {
    try {
      const [sessRes, statusRes] = await Promise.all([
        portalFetch("/api/auth/session"),
        portalFetch("/api/portal/status"),
      ]);

      if (!sessRes.ok) {
        throw new Error("Unable to verify authentication session.");
      }

      if (!statusRes.ok) {
        throw new Error("Unable to retrieve portal status.");
      }

      const sess = await sessRes.json();
      const st = await statusRes.json();

      setSignedInUser(
        sess.authenticated ? sess.username : null
      );

      if (!st.service_available) {
        serviceAlert.hidden = false;
        serviceAlertText.textContent =
          st.message || "Service is temporarily unavailable.";
      } else {
        serviceAlert.hidden = true;
      }

    } catch (error) {
      // Background status polling should not interrupt the user.
      console.warn("Portal background status check failed:", error);
    }
  }

  // --------------------------------------------------
  // EDUCATIONAL EXPLORER TABS
  // --------------------------------------------------

  document.querySelectorAll(".portal-tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      const target = tab.dataset.section;

      document.querySelectorAll(".portal-tab").forEach((t) => {
        t.classList.toggle("active", t === tab);
      });

      document.querySelectorAll(".portal-section").forEach((section) => {
        const active = section.id === `sec-${target}`;

        section.hidden = !active;
        section.classList.toggle("active", active);
      });
    });
  });

  // --------------------------------------------------
  // USER LOGIN
  // --------------------------------------------------

  if (loginForm) {
    loginForm.addEventListener("submit", async (event) => {
      event.preventDefault();

      const username = document
        .getElementById("portal-username")
        .value.trim();

      const password = document
        .getElementById("portal-password")
        .value;

      loginFeedback.hidden = false;
      loginFeedback.textContent = "Verifying credentials...";

      try {
        const response = await portalFetch("/api/auth/login", {
          method: "POST",

          headers: {
            "Content-Type": "application/json",
          },

          body: JSON.stringify({
            username,
            password,
          }),
        });

        const data = await response.json();

        if (response.ok && data.authenticated) {

          if (data.token) {
            setPortalToken(data.token);
          }

          loginFeedback.hidden = true;

          document.getElementById("portal-password").value = "";

          setSignedInUser(data.username);

          // Refresh session and service status after login.
          refreshSessionAndStatus();

        } else {
          loginFeedback.textContent =
            data.error || "Sign-in failed. Please try again.";
        }

      } catch (error) {
        console.error("Portal login error:", error);

        loginFeedback.textContent =
          "Unable to reach authentication service. Please try again.";
      }
    });
  }

  // --------------------------------------------------
  // USER LOGOUT
  // --------------------------------------------------

  if (logoutBtn) {
    logoutBtn.addEventListener("click", async () => {
      try {
        await portalFetch("/api/auth/logout", {
          method: "POST",
        });

      } catch (error) {
        console.error("Logout request failed:", error);

      } finally {
        setPortalToken(null);

        resourceOutput.hidden = true;

        setSignedInUser(null);

        if (loginFeedback) {
          loginFeedback.hidden = true;
        }
      }
    });
  }

  // --------------------------------------------------
  // LOAD PUBLIC RESOURCES
  // --------------------------------------------------

  const resourceButton = document.getElementById(
    "btn-fetch-portal-resources"
  );

  if (resourceButton) {
    resourceButton.addEventListener("click", async () => {
      resourceOutput.hidden = false;
      resourceOutput.textContent = "Loading active modules...";

      try {
        const response = await portalFetch("/api/records/public");

        const data = await response.json();

        if (!response.ok) {
          resourceOutput.textContent =
            data.error || "Unable to load modules right now.";

          return;
        }

        const modules = Array.isArray(data.modules)
          ? data.modules
          : [];

        resourceOutput.replaceChildren();

        modules.forEach((module) => {
          const item = document.createElement("div");
          const name = document.createElement("strong");

          name.textContent = module.name || "Module";

          item.appendChild(name);
          item.appendChild(
            document.createTextNode(
              ` — ${module.state || "Unknown"}`
            )
          );

          resourceOutput.appendChild(item);
        });

      } catch (error) {
        console.error("Resource loading error:", error);

        resourceOutput.textContent =
          "Service temporarily unavailable.";
      }
    });
  }

  // --------------------------------------------------
  // ADMIN DIAGNOSTIC ACCESS PROBE
  // --------------------------------------------------

  const adminProbeButton = document.getElementById(
    "btn-probe-admin-diag"
  );

  if (adminProbeButton) {
    adminProbeButton.addEventListener("click", async () => {
      resourceOutput.hidden = false;
      resourceOutput.textContent = "Checking access...";

      try {
        const response = await portalFetch(
          "/api/admin/debug-console"
        );

        const data = await response.json();

        resourceOutput.textContent =
          data.error || "Access denied.";

      } catch (error) {
        console.error("Admin diagnostic request failed:", error);

        resourceOutput.textContent = "Access denied.";
      }
    });
  }

  // --------------------------------------------------
  // INITIALIZE PORTAL
  // --------------------------------------------------

  function initializePortal() {
    console.log(
      "CyberShield API destination:",
      resolveUrl("/api/auth/session")
    );

    refreshSessionAndStatus();

    // Check session periodically.
    window.setInterval(refreshSessionAndStatus, 5000);
  }

  if (document.readyState === "loading") {
    document.addEventListener(
      "DOMContentLoaded",
      initializePortal,
      { once: true }
    );
  } else {
    initializePortal();
  }

})();
