/** API client helpers (shared via importScripts in service worker). */

const DEFAULT_API_BASE = "http://127.0.0.1:5000";

async function getConfig() {
  const data = await chrome.storage.sync.get({
    apiBase: DEFAULT_API_BASE,
    apiToken: "",
    autoScan: true,
    showWarnings: true,
  });
  data.apiBase = normalizeApiBase(data.apiBase || DEFAULT_API_BASE);
  return data;
}

function normalizeApiBase(value) {
  return String(value || "")
    .trim()
    .replace(/\/+$/, "");
}

function originPattern(apiBase) {
  const url = new URL(normalizeApiBase(apiBase));
  return `${url.origin}/*`;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isRetryableFetchError(err, status) {
  if (status === 502 || status === 503 || status === 504) return true;
  const msg = String(err?.message || err || "");
  return /failed to fetch|networkerror|load failed|aborted|the user aborted|waking up/i.test(msg);
}

async function fetchWithRetry(url, options, { retries = 3, timeoutMs = 90000 } = {}) {
  let lastError = new Error("Request failed");
  for (let attempt = 0; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, { ...options, signal: controller.signal, cache: "no-store" });
      clearTimeout(timer);
      if (res.status === 502 || res.status === 503 || res.status === 504) {
        throw new Error(`Server waking up (${res.status})`);
      }
      return res;
    } catch (err) {
      clearTimeout(timer);
      lastError = err;
      if (!isRetryableFetchError(err) || attempt === retries) {
        break;
      }
      await sleep(1000 * 2 ** attempt);
    }
  }
  throw lastError;
}

function friendlyNetworkError(err, apiBase) {
  const msg = String(err?.message || err || "");
  if (/aborted|timeout/i.test(msg)) {
    return "The API timed out. If the site was idle it may still be waking up — try again.";
  }
  if (isRetryableFetchError(err)) {
    return (
      `Could not reach ${apiBase}. Check the API base URL, that the server is running, ` +
      "and that PhishGuard is allowed to access that site in Settings. " +
      "A hosted demo can take ~30s to wake after idle time."
    );
  }
  return msg;
}

async function scanEmail(payload) {
  const cfg = await getConfig();
  if (!cfg.apiToken) {
    throw new Error("API token not configured. Open extension settings.");
  }

  const allowed = await chrome.permissions.contains({ origins: [originPattern(cfg.apiBase)] });
  if (!allowed) {
    throw new Error(
      `No permission for ${cfg.apiBase}. Open Settings, save the API base URL, and allow access when Chrome asks.`
    );
  }

  try {
    const res = await fetchWithRetry(`${cfg.apiBase}/api/v1/extension/scan`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${cfg.apiToken}`,
      },
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err?.error?.message || `Scan failed (${res.status})`);
    }
    return res.json();
  } catch (err) {
    throw new Error(friendlyNetworkError(err, cfg.apiBase));
  }
}

async function pingHealth(apiBase) {
  const base = normalizeApiBase(apiBase);
  const res = await fetchWithRetry(
    `${base}/api/v1/health`,
    { method: "GET" },
    { retries: 4, timeoutMs: 20000 }
  );
  if (!res.ok) {
    throw new Error(`Health check failed (${res.status})`);
  }
  return res.json();
}
