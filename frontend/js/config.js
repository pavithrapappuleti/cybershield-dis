
/**
 * CyberShield Environment-Aware API Configuration
 */

window.CYBERSHIELD_CONFIG = (() => {
  const host = window.location.hostname;

  const isLocalhost =
    host === "127.0.0.1" ||
    host === "localhost";

  const isRender =
    host.endsWith(".onrender.com");

  const apiBase =
    isLocalhost || isRender
      ? ""
      : "https://cybershield-dis-1.onrender.com";

  return {
    API_BASE_URL: apiBase,

    buildUrl: (path) => {
      if (/^https?:\/\//i.test(path)) {
        return path;
      }

      return `${apiBase}/${path.replace(/^\/+/, "")}`;
    },
  };
})();
