(function () {
  const ENDPOINT = "/api/logs";
  const PREVIEW_LINES = 20;
  const DETAIL_LINES = 400;

  function ready(fn) {
    if (document.readyState === "loading") {
      document.addEventListener("DOMContentLoaded", fn, { once: true });
    } else {
      fn();
    }
  }

  function formatEntry(entry) {
    const ts = entry && entry.timestamp ? entry.timestamp : "—";
    const src =
      entry && typeof entry.source === "string" && entry.source
        ? `[${entry.source}] `
        : "";
    const msg = entry && entry.message ? entry.message : "";
    return `${ts} ${src}${msg}`;
  }

  async function fetchLogs(lines) {
    const url = `${ENDPOINT}?lines=${lines}`;
    const res = await fetch(url, { credentials: "same-origin" });

    if (res.status === 401) {
      throw new Error("auth");
    }
    if (res.status === 403) {
      throw new Error("forbidden");
    }
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}`);
    }
    return res.json();
  }

  function setError(el, message) {
    if (!el) return;
    if (message) {
      el.textContent = message;
      el.hidden = false;
    } else {
      el.textContent = "";
      el.hidden = true;
    }
  }

  function renderPreview(container, entries) {
    if (!container) return;
    container.innerHTML = "";

    if (!entries || !entries.length) {
      const empty = document.createElement("div");
      empty.className = "log-empty";
      empty.textContent = "Aucune entrée journald disponible.";
      container.appendChild(empty);
      return;
    }

    entries.forEach((entry) => {
      const line = document.createElement("div");
      line.className = "log-line";

      const ts = document.createElement("span");
      ts.className = "log-ts";
      ts.textContent = entry.timestamp || "—";

      const src = document.createElement("span");
      src.className = "log-src";
      src.textContent = entry.source ? entry.source : "";
      if (!src.textContent) {
        src.style.display = "none";
      }

      const msg = document.createElement("span");
      msg.className = "log-msg";
      msg.textContent = entry.message || "";

      line.appendChild(ts);
      line.appendChild(src);
      line.appendChild(msg);
      container.appendChild(line);
    });
  }

  function renderFull(container, entries) {
    if (!container) return;
    if (!entries || !entries.length) {
      container.textContent = "(aucune entrée journald disponible)";
      return;
    }
    container.textContent = entries.map(formatEntry).join("\n");
  }

  function initPreviewTile() {
    const card = document.querySelector('[data-role="logs-card"]');
    if (!card) return;

    const list = card.querySelector('[data-role="logs-list"]');
    const errorEl = card.querySelector('[data-role="logs-error"]');
    const refreshBtn = card.querySelector('[data-role="logs-refresh"]');
    const lines = Number(card.dataset.lines) || PREVIEW_LINES;

    const load = async () => {
      if (list) {
        list.innerHTML = '<div class="log-empty">Chargement…</div>';
      }
      setError(errorEl, "");
      try {
        const data = await fetchLogs(lines);
        renderPreview(list, data.entries || []);
        if (data.truncated && card.dataset.truncated !== "1") {
          card.dataset.truncated = "1";
        }
      } catch (err) {
        let message = "Lecture des logs impossible.";
        if (err && err.message === "auth") {
          message = "Jeton requis pour lire les logs.";
          if (typeof showTokenPrompt === "function") {
            showTokenPrompt(message);
          }
        } else if (err && err.message === "forbidden") {
          message = "Accès aux logs refusé pour cette IP/token.";
        }
        setError(errorEl, message);
      }
    };

    if (refreshBtn) {
      refreshBtn.addEventListener("click", () => {
        load();
      });
    }

    load();
  }

  function initLogsPage() {
    const page = document.getElementById("logsPage");
    if (!page) return;

    const body = page.querySelector('[data-role="logs-full"]');
    const errorEl = page.querySelector('[data-role="logs-error"]');
    const refreshBtn = page.querySelector('[data-role="logs-refresh"]');
    const lines = Number(page.dataset.lines) || DETAIL_LINES;

    const load = async () => {
      if (body) {
        body.textContent = "Chargement…";
      }
      setError(errorEl, "");
      try {
        const data = await fetchLogs(lines);
        renderFull(body, data.entries || []);
        if (data.truncated && body) {
          body.textContent += `\n… (tronqué à ${lines} lignes)`;
        }
      } catch (err) {
        let message = "Lecture des logs impossible.";
        if (err && err.message === "auth") {
          message = "Jeton requis pour lire les logs.";
          if (typeof showTokenPrompt === "function") {
            showTokenPrompt(message);
          }
        } else if (err && err.message === "forbidden") {
          message = "Accès aux logs refusé pour cette IP/token.";
        }
        setError(errorEl, message);
      }
    };

    if (refreshBtn) {
      refreshBtn.addEventListener("click", () => load());
    }

    load();
  }

  ready(() => {
    initPreviewTile();
    initLogsPage();
  });
})();
