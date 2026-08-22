document.addEventListener("DOMContentLoaded", async () => {
  const status = document.getElementById("status");
  const cfg = await chrome.storage.sync.get({ apiToken: "", apiBase: "http://127.0.0.1:5000", autoScan: true });
  if (!cfg.apiToken) {
    status.textContent = "API token missing — open Settings.";
  } else {
    status.textContent = `API: ${cfg.apiBase} · Auto-scan: ${cfg.autoScan ? "ON" : "OFF"}`;
  }

  document.getElementById("open-settings").addEventListener("click", () => {
    chrome.runtime.openOptionsPage();
  });

  document.getElementById("rescan").addEventListener("click", async () => {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;
    chrome.tabs.sendMessage(tab.id, { type: "MANUAL_RESCAN" }, () => {
      // content script listens via window hook; inject call
    });
    chrome.scripting?.executeScript?.({
      target: { tabId: tab.id },
      func: () => window.PhishGuardRescan?.(),
    });
    status.textContent = "Rescan requested…";
  });
});
