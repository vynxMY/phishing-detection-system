document.addEventListener("DOMContentLoaded", async () => {
  const defaults = {
    apiBase: "http://127.0.0.1:5000",
    apiToken: "",
    autoScan: true,
    showWarnings: true,
    scanAttachments: true,
    explanationLevel: "simple",
  };
  const msg = document.getElementById("msg");
  const cfg = await chrome.storage.sync.get(defaults);
  document.getElementById("apiBase").value = cfg.apiBase;
  document.getElementById("apiToken").value = cfg.apiToken;
  document.getElementById("autoScan").checked = cfg.autoScan;
  document.getElementById("showWarnings").checked = cfg.showWarnings;
  document.getElementById("scanAttachments").checked = cfg.scanAttachments !== false;
  document.getElementById("explanationLevel").value = cfg.explanationLevel || "simple";

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

  async function syncServerPrefs(apiBase, apiToken, prefs) {
    if (!apiToken) return;
    const res = await fetch(`${apiBase}/api/v1/extension/settings`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiToken}`,
      },
      body: JSON.stringify({
        auto_scan: prefs.autoScan,
        show_warnings: prefs.showWarnings,
        scan_attachments: prefs.scanAttachments,
        explanation_level: prefs.explanationLevel,
      }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.error?.message || `Could not sync settings (${res.status})`);
    }
  }

  async function loadServerPrefs(apiBase, apiToken) {
    if (!apiToken) return null;
    const res = await fetch(`${apiBase}/api/v1/extension/settings`, {
      headers: { Authorization: `Bearer ${apiToken}` },
      cache: "no-store",
    });
    if (!res.ok) return null;
    return res.json();
  }

  // Pull server prefs when token+base already saved
  try {
    const remote = await loadServerPrefs(cfg.apiBase, cfg.apiToken);
    if (remote) {
      if (typeof remote.auto_scan === "boolean") {
        document.getElementById("autoScan").checked = remote.auto_scan;
      }
      if (typeof remote.show_warnings === "boolean") {
        document.getElementById("showWarnings").checked = remote.show_warnings;
      }
      if (typeof remote.scan_attachments === "boolean") {
        document.getElementById("scanAttachments").checked = remote.scan_attachments;
      }
      if (remote.explanation_level) {
        document.getElementById("explanationLevel").value = remote.explanation_level;
      }
    }
  } catch {
    /* local defaults stay */
  }

  document.getElementById("save").addEventListener("click", async () => {
    const apiBase = document.getElementById("apiBase").value.trim().replace(/\/+$/, "");
    const apiToken = document.getElementById("apiToken").value.trim();
    const prefs = {
      autoScan: document.getElementById("autoScan").checked,
      showWarnings: document.getElementById("showWarnings").checked,
      scanAttachments: document.getElementById("scanAttachments").checked,
      explanationLevel: document.getElementById("explanationLevel").value || "simple",
    };
    try {
      const granted = await ensurePermission(apiBase);
      if (!granted) {
        showMsg("Chrome blocked access to that site. Allow it or scans will fail with “Failed to fetch”.", false);
        return;
      }
      await chrome.storage.sync.set({
        apiBase,
        apiToken,
        ...prefs,
      });
      try {
        await syncServerPrefs(apiBase, apiToken, prefs);
        showMsg("Saved locally and synced to your PhishGuard account.");
      } catch (syncErr) {
        showMsg(`Saved locally. Server sync: ${syncErr.message || syncErr}`, false);
      }
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
