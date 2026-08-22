document.addEventListener("DOMContentLoaded", async () => {
  const defaults = {
    apiBase: "http://127.0.0.1:5000",
    apiToken: "",
    autoScan: true,
    showWarnings: true,
  };
  const msg = document.getElementById("msg");
  const cfg = await chrome.storage.sync.get(defaults);
  document.getElementById("apiBase").value = cfg.apiBase;
  document.getElementById("apiToken").value = cfg.apiToken;
  document.getElementById("autoScan").checked = cfg.autoScan;
  document.getElementById("showWarnings").checked = cfg.showWarnings;

  function showMsg(text, ok = true) {
    msg.textContent = text;
    msg.style.color = ok ? "#3dba7c" : "#e07a5f";
  }

  async function ensurePermission(apiBase) {
    let origin;
    try {
      origin = new URL(apiBase).origin + "/*";
    } catch {
      throw new Error("Invalid API base URL.");
    }
    const already = await chrome.permissions.contains({ origins: [origin] });
    if (already) return true;
    return chrome.permissions.request({ origins: [origin] });
  }

  document.getElementById("save").addEventListener("click", async () => {
    const apiBase = document.getElementById("apiBase").value.trim().replace(/\/+$/, "");
    const apiToken = document.getElementById("apiToken").value.trim();
    try {
      const granted = await ensurePermission(apiBase);
      if (!granted) {
        showMsg("Chrome blocked access to that site. Allow it or scans will fail with “Failed to fetch”.", false);
        return;
      }
      await chrome.storage.sync.set({
        apiBase,
        apiToken,
        autoScan: document.getElementById("autoScan").checked,
        showWarnings: document.getElementById("showWarnings").checked,
      });
      showMsg("Saved. Reload Gmail if a scan is already open.");
    } catch (err) {
      showMsg(String(err.message || err), false);
    }
  });

  document.getElementById("test").addEventListener("click", async () => {
    const apiBase = document.getElementById("apiBase").value.trim().replace(/\/+$/, "");
    showMsg("Testing connection…");
    try {
      const granted = await ensurePermission(apiBase);
      if (!granted) {
        showMsg("Allow site access first, then test again.", false);
        return;
      }
      const res = await fetch(`${apiBase}/api/v1/health`, { cache: "no-store" });
      if (!res.ok) {
        throw new Error(`Health check failed (${res.status})`);
      }
      const body = await res.json().catch(() => ({}));
      showMsg(`Connected: ${body.service || "ok"} @ ${apiBase}`);
    } catch (err) {
      const text = String(err.message || err);
      if (/failed to fetch|networkerror|load failed/i.test(text)) {
        showMsg(
          `Could not reach ${apiBase}. If this is a hosted URL it may be waking up — wait 30s and test again.`,
          false
        );
        return;
      }
      showMsg(text, false);
    }
  });
});
