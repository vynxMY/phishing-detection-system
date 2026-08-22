/* global chrome */

importScripts("../utils/api-client.js");

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "SCAN_EMAIL") {
    (async () => {
      try {
        const cfg = await getConfig();
        if (!cfg.autoScan && message.payload?.source === "auto") {
          sendResponse({ skipped: true, reason: "auto_scan_disabled" });
          return;
        }
        if (!cfg.showWarnings && message.payload?.source === "auto") {
          sendResponse({ skipped: true, reason: "warnings_disabled" });
          return;
        }
        const result = await scanEmail(message.payload);
        sendResponse({ ok: true, result });
      } catch (err) {
        sendResponse({ ok: false, error: String(err.message || err) });
      }
    })();
    return true; // async response
  }

  if (message?.type === "GET_CONFIG") {
    getConfig().then((cfg) => sendResponse(cfg));
    return true;
  }

  return false;
});
