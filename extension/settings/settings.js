document.addEventListener("DOMContentLoaded", async () => {
  const defaults = {
    apiBase: "http://127.0.0.1:5000",
    apiToken: "",
    autoScan: true,
    showWarnings: true,
  };
  const cfg = await chrome.storage.sync.get(defaults);
  document.getElementById("apiBase").value = cfg.apiBase;
  document.getElementById("apiToken").value = cfg.apiToken;
  document.getElementById("autoScan").checked = cfg.autoScan;
  document.getElementById("showWarnings").checked = cfg.showWarnings;

  document.getElementById("save").addEventListener("click", async () => {
    await chrome.storage.sync.set({
      apiBase: document.getElementById("apiBase").value.trim().replace(/\/$/, ""),
      apiToken: document.getElementById("apiToken").value.trim(),
      autoScan: document.getElementById("autoScan").checked,
      showWarnings: document.getElementById("showWarnings").checked,
    });
    document.getElementById("msg").textContent = "Saved.";
  });
});
