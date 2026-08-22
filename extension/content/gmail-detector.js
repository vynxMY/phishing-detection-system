/** Observe Gmail DOM and trigger scans when a message is opened. */

(function () {
  let lastKey = "";
  let debounceTimer = null;

  function messageKey(data) {
    return `${data.subject}|${data.sender}|${(data.body || "").slice(0, 120)}`;
  }

  function sendScan(message, attempt) {
    chrome.runtime.sendMessage(message, (response) => {
      const portErr = chrome.runtime.lastError?.message || "";
      if (/receiving end does not exist|message port closed|back.?page/i.test(portErr) && attempt < 3) {
        setTimeout(() => sendScan(message, attempt + 1), 250 * (attempt + 1));
        return;
      }
      if (portErr) {
        window.PhishGuardUI?.showError(portErr);
        return;
      }
      if (response?.skipped) return;
      if (!response?.ok) {
        window.PhishGuardUI?.showError(response?.error || "Scan failed");
        return;
      }
      window.PhishGuardUI?.showResult(response.result);
    });
  }

  function maybeScan(source) {
    if (!window.PhishGuardExtract) return;
    const data = window.PhishGuardExtract.extractOpenEmail();
    if (!data.subject && !data.body) return;
    const key = messageKey(data);
    if (key === lastKey && source === "auto") return;
    lastKey = key;

    sendScan(
      {
        type: "SCAN_EMAIL",
        payload: {
          subject: data.subject,
          sender: data.sender,
          body: data.body,
          links: data.links,
          source,
        },
      },
      0
    );
  }

  const observer = new MutationObserver(() => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => maybeScan("auto"), 600);
  });

  observer.observe(document.body, { childList: true, subtree: true });

  window.PhishGuardRescan = () => maybeScan("manual");
})();
