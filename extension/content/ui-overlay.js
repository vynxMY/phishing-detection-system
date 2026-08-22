/** Risk badge + side panel overlay on Gmail. */

(function () {
  const ROOT_ID = "phishguard-root";

  function ensureRoot() {
    let root = document.getElementById(ROOT_ID);
    if (root) return root;
    root = document.createElement("div");
    root.id = ROOT_ID;
    document.body.appendChild(root);
    return root;
  }

  function classFor(score) {
    if (score >= 80) return "pg-critical";
    if (score >= 60) return "pg-high";
    if (score >= 40) return "pg-warn";
    if (score >= 20) return "pg-low";
    return "pg-safe";
  }

  function showResult(result) {
    const root = ensureRoot();
    const cls = classFor(result.risk_score || 0);
    const findings = (result.explanations?.findings || [])
      .slice(0, 5)
      .map((f) => `<li>${escapeHtml(f.text || "")}</li>`)
      .join("");

    root.innerHTML = `
      <div class="pg-banner ${cls}">
        <strong>PhishGuard</strong>
        <span>${result.risk_score}/100 · ${(result.classification || "").replace("_", " ").toUpperCase()}</span>
        <button type="button" class="pg-toggle">Details</button>
        <button type="button" class="pg-close" aria-label="Close">×</button>
      </div>
      <aside class="pg-panel ${cls}" hidden>
        <p>${escapeHtml(result.explanations?.simple || "")}</p>
        <ul>${findings}</ul>
        <div class="pg-advice">
          <strong>Do not:</strong>
          <ul>${(result.advice?.do_not || []).map((x) => `<li>${escapeHtml(x)}</li>`).join("")}</ul>
        </div>
        <a class="pg-full" href="#" target="_blank" rel="noopener">View full analysis</a>
        <button type="button" class="pg-rescan">Rescan</button>
      </aside>
    `;

    const full = root.querySelector(".pg-full");
    if (full && result.scan_id) {
      chrome.runtime.sendMessage({ type: "GET_CONFIG" }, (cfg) => {
        if (cfg?.apiBase) {
          full.href = `${String(cfg.apiBase).replace(/\/+$/, "")}/scan/${result.scan_id}`;
        } else {
          full.remove();
        }
      });
    } else if (full) {
      full.remove();
    }

    root.querySelector(".pg-close")?.addEventListener("click", () => {
      root.innerHTML = "";
    });
    root.querySelector(".pg-toggle")?.addEventListener("click", () => {
      const panel = root.querySelector(".pg-panel");
      if (panel) panel.hidden = !panel.hidden;
    });
    root.querySelector(".pg-rescan")?.addEventListener("click", () => {
      window.PhishGuardRescan?.();
    });
  }

  function showError(message) {
    const root = ensureRoot();
    root.innerHTML = `
      <div class="pg-banner pg-warn">
        <strong>PhishGuard</strong>
        <span>${escapeHtml(message)}</span>
        <button type="button" class="pg-close" aria-label="Close">×</button>
      </div>
    `;
    root.querySelector(".pg-close")?.addEventListener("click", () => {
      root.innerHTML = "";
    });
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  window.PhishGuardUI = { showResult, showError };
})();
