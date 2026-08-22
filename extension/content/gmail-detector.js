/** Observe Gmail DOM and trigger scans when a message is opened. */

(function () {
  let lastKey = "";
  let debounceTimer = null;

  function messageKey(data) {
    return `${data.subject}|${data.sender}|${(data.body || "").slice(0, 120)}`;
  }

  function maybeScan(source) {
    if (!window.PhishGuardExtract) return;
    const data = window.PhishGuardExtract.extractOpenEmail();
    if (!data.subject && !data.body) return;
    const key = messageKey(data);
    if (key === lastKey && source === "auto") return;
    lastKey = key;

    chrome.runtime.sendMessage(
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
      (response) => {
        if (chrome.runtime.lastError) {
          window.PhishGuardUI?.showError(chrome.runtime.lastError.message);
          return;
        }
        if (response?.skipped) return;
        if (!response?.ok) {
          window.PhishGuardUI?.showError(response?.error || "Scan failed");
          return;
        }
        window.PhishGuardUI?.showResult(response.result);
      }
    );
  }

  const observer = new MutationObserver(() => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => maybeScan("auto"), 600);
  });

  observer.observe(document.body, { childList: true, subtree: true });

  // Manual rescan hook
  window.PhishGuardRescan = () => maybeScan("manual");
})();
