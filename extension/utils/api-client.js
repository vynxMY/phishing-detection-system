/** API client helpers (shared via importScripts in service worker). */

async function getConfig() {
  const data = await chrome.storage.sync.get({
    apiBase: "http://127.0.0.1:5000",
    apiToken: "",
    autoScan: true,
    showWarnings: true,
  });
  return data;
}

async function scanEmail(payload) {
  const cfg = await getConfig();
  if (!cfg.apiToken) {
    throw new Error("API token not configured. Open extension settings.");
  }
  const res = await fetch(`${cfg.apiBase}/api/v1/extension/scan`, {
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
}
