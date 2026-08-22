function classLabel(value) {
  return String(value || "").replace(/_/g, " ");
}

function hostnameOf(url) {
  try {
    return new URL(url).hostname || url;
  } catch {
    return url || "Unknown page";
  }
}

function isGmail(url) {
  try {
    return new URL(url).hostname === "mail.google.com";
  } catch {
    return false;
  }
}

function renderResult(result, apiBase) {
  const box = document.getElementById("result");
  const badge = document.getElementById("class-badge");
  const bar = document.getElementById("score-bar");
  const num = document.getElementById("score-num");
  const signals = document.getElementById("signals");
  const link = document.getElementById("full-analysis");
  const score = Number(result.risk_score || 0);
  const cls = result.classification || "";

  box.hidden = false;
  badge.textContent = classLabel(cls) || "Result";
  badge.className = `badge ${cls}`;
  bar.style.width = `${Math.max(0, Math.min(100, score))}%`;
  num.textContent = `${score}%`;
  signals.innerHTML = (result.explanations?.findings || [])
    .slice(0, 3)
    .map((f) => `<li>⚠ ${escapeHtml(f.text || f.category || "Indicator")}</li>`)
    .join("");
  if (result.scan_id && apiBase) {
    link.href = `${apiBase.replace(/\/+$/, "")}/scan/${result.scan_id}`;
    link.hidden = false;
  } else {
    link.hidden = true;
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

document.addEventListener("DOMContentLoaded", async () => {
  const status = document.getElementById("status");
  const hostEl = document.getElementById("host");
  const modeLabel = document.getElementById("mode-label");
  const scanBtn = document.getElementById("scan-now");

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const tabUrl = tab?.url || "";
  const gmail = isGmail(tabUrl);
  hostEl.textContent = gmail ? "Opened Gmail message" : hostnameOf(tabUrl);
  modeLabel.textContent = gmail ? "Gmail" : "Current website";
  scanBtn.textContent = gmail ? "Rescan current email" : "Analyze this page";

  chrome.runtime.sendMessage({ type: "GET_CONFIG" }, (cfg) => {
    if (!cfg?.apiToken) {
      status.textContent = "API token missing — open Settings.";
      return;
    }
    status.textContent = `Connected to ${cfg.apiBase}`;
  });

  document.getElementById("open-settings").addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });

  scanBtn.addEventListener("click", async () => {
    status.textContent = "Analysing…";
    document.getElementById("result").hidden = true;

    if (gmail) {
      if (!tab?.id) {
        status.textContent = "No active tab.";
        return;
      }
      chrome.scripting?.executeScript?.({
        target: { tabId: tab.id },
        func: () => window.PhishGuardRescan?.(),
      });
      status.textContent = "Rescan requested in Gmail. Open the banner for details, or use View full analysis after the scan finishes.";
      return;
    }

    chrome.runtime.sendMessage({ type: "SCAN_URL", url: tabUrl }, (response) => {
      const err = chrome.runtime.lastError?.message;
      if (err) {
        status.textContent = err;
        return;
      }
      if (!response?.ok) {
        status.textContent = response?.error || "Scan failed";
        return;
      }
      chrome.runtime.sendMessage({ type: "GET_CONFIG" }, (cfg) => {
        renderResult(response.result, cfg?.apiBase);
        status.textContent = "Full explanation opens on the website (sign in if prompted).";
      });
    });
  });
});
