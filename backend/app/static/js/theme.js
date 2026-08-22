(function () {
  const KEY = "phishguard-theme";

  function systemTheme() {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function current() {
    return localStorage.getItem(KEY) || systemTheme();
  }

  function apply(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    const btn = document.getElementById("theme-toggle");
    if (btn) {
      btn.setAttribute("aria-pressed", theme === "dark" ? "true" : "false");
      btn.title = theme === "dark" ? "Switch to light mode" : "Switch to dark mode";
      btn.setAttribute("aria-label", btn.title);
      btn.textContent = theme === "dark" ? "Light" : "Dark";
    }
  }

  apply(current());

  document.addEventListener("DOMContentLoaded", () => {
    apply(current());
    document.getElementById("theme-toggle")?.addEventListener("click", () => {
      const next = current() === "dark" ? "light" : "dark";
      localStorage.setItem(KEY, next);
      apply(next);
    });
    document.getElementById("nav-toggle")?.addEventListener("click", () => {
      document.getElementById("site-nav")?.classList.toggle("open");
    });
    document.querySelectorAll("form.js-scan-form").forEach((form) => {
      form.addEventListener("submit", () => {
        const overlay = document.getElementById("scan-overlay");
        if (overlay) overlay.hidden = false;
      });
    });
    document.querySelectorAll("[data-account-toggle]").forEach((btn) => {
      btn.addEventListener("click", (ev) => {
        ev.stopPropagation();
        btn.parentElement?.classList.toggle("open");
      });
    });
    document.addEventListener("click", () => {
      document.querySelectorAll(".account-menu.open").forEach((el) => el.classList.remove("open"));
    });
  });
})();
