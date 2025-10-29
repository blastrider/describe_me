pub(super) fn render_index(web_debug: bool, csp_nonce: &str) -> String {
    INDEX_HTML
        .replace("__WEB_DEBUG__", if web_debug { "true" } else { "false" })
        .replace("__CSP_NONCE__", csp_nonce)
}

const INDEX_HTML: &str = r#"<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1, viewport-fit=cover">
  <title>describe_me — Live</title>
  <style nonce="__CSP_NONCE__">
    :root {
      --bg: #0f1115;
      --card: #151923;
      --text: #e6eef8;
      --muted: #a8b3c3;
      --ok: #3ad29f;
      --warn: #ffd166;
      --err: #ff6b6b;
      --mono: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
    }
    * { box-sizing: border-box; }
    html, body { height: 100%; }
    body {
      margin: 0; background: var(--bg); color: var(--text);
      font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, sans-serif;
    }
    header {
      padding: 16px 20px; border-bottom: 1px solid #222838;
      display: flex; align-items: center; gap: 10px;
    }
    .dot {
      width: 10px; height: 10px; border-radius: 999px; background: var(--warn);
      box-shadow: 0 0 8px var(--warn);
      display: inline-block; flex-shrink: 0;
    }
    .ok { background: var(--ok); box-shadow: 0 0 8px var(--ok); }
    .dot.err { background: var(--err); box-shadow: 0 0 8px var(--err); }
    main { padding: 20px; display: grid; gap: 16px; max-width: 1200px; margin: 0 auto; }
    .grid {
      display: grid; gap: 16px;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    }
    .card {
      background: var(--card); border: 1px solid #222838; border-radius: 10px;
      padding: 16px; box-shadow: 0 4px 12px rgba(0,0,0,.2);
    }
    h1 { font-size: 18px; margin: 0; }
    h2 { font-size: 16px; margin: 0 0 10px; color: var(--muted); }
    .k { color: var(--muted); }
    .v { font-family: var(--mono); }
    .mono { font-family: var(--mono); font-size: 14px; }
    .row { display: flex; justify-content: space-between; gap: 10px; margin: 6px 0; }
    .badge { padding: 2px 8px; border-radius: 999px; background: #1d2333; border: 1px solid #2a3147; }
    .footer { opacity: .7; font-size: 13px; text-align: center; padding: 10px 0 30px; }
    .error { color: var(--err); }
    .link-button {
      background: none; border: none; color: inherit; font: inherit;
      text-decoration: underline; cursor: pointer; padding: 0;
    }
    .link-button:hover { text-decoration: none; }
    @media (prefers-color-scheme: light) {
      :root { --bg:#f6f7fb; --card:#ffffff; --text:#1d2330; --muted:#5b667a; }
      body { background: var(--bg); color: var(--text); }
      .card { border-color: #e4e8f1; }
    }
     .bar { position: relative; height: 10px; background: #1d2333; border:1px solid #2a3147; border-radius:6px; overflow:hidden; }
     .bar > span { position:absolute; left:0; top:0; bottom:0; background:#3ad29f55; border-right:2px solid #3ad29f; }
     .mono .line { margin: 6px 0 10px; }
    .services-list { display: flex; flex-direction: column; gap: 10px; }
    .service-row {
      display: flex; align-items: flex-start; gap: 10px;
      padding: 8px 10px; border-radius: 8px; background: #1d2333; border: 1px solid #2a3147;
    }
    .service-dot { margin-top: 4px; }
    .service-name { font-weight: 600; }
    .service-meta { margin-top: 2px; font-size: 13px; color: var(--muted); }
    .service-empty { color: var(--muted); font-style: italic; }
    @media (prefers-color-scheme: light) {
      .service-row { background: #f0f2fb; border-color: #d6dbeb; }
    }
    .token-overlay {
      position: fixed; inset: 0;
      background: rgba(15, 17, 21, 0.92);
      display: none; align-items: center; justify-content: center;
      padding: 20px; z-index: 100;
    }
    .token-overlay.visible { display: flex; }
    .token-dialog {
      background: var(--card); border: 1px solid #222838; border-radius: 10px;
      padding: 24px; max-width: 360px; width: 100%;
      box-shadow: 0 8px 24px rgba(0,0,0,.35);
    }
    .token-dialog h2 { margin: 0 0 12px; font-size: 18px; color: var(--text); }
    .token-dialog p { margin: 0 0 16px; color: var(--muted); font-size: 14px; }
    .token-dialog form { display: flex; flex-direction: column; gap: 10px; }
    .token-dialog input {
      padding: 10px 12px; border-radius: 6px; border: 1px solid #2a3147;
      background: #0f1115; color: var(--text); font-size: 15px;
    }
    .token-dialog .actions {
      display: flex; gap: 10px; margin-top: 12px; flex-wrap: wrap;
    }
    .token-dialog button {
      flex: 1 1 auto; padding: 10px 12px; border-radius: 6px; border: none;
      background: #3ad29f; color: #0f1115; font-weight: 600; cursor: pointer;
    }
    .token-dialog button.secondary {
      background: transparent; border: 1px solid #2a3147; color: var(--text);
    }
    .token-error { margin-top: 12px; font-size: 13px; color: var(--err); }
    @media (prefers-color-scheme: light) {
      .token-dialog { background: #ffffff; border-color: #d6dbeb; }
      .token-dialog input { background: #ffffff; border-color: #d0d6e5; color: #1d2330; }
      .token-dialog button.secondary { border-color: #d0d6e5; color: #1d2330; }
    }

  </style>
</head>
<body>
  <header>
    <div id="statusDot" class="dot"></div>
    <h1>describe_me — informations en direct</h1>
    <span class="badge" id="lastUpdate">—</span>
  </header>

  <main>
    <div class="grid">
      <section class="card">
        <h2>Système</h2>
        <div class="row"><span class="k">Hostname</span><span class="v" id="hostname">—</span></div>
        <div class="row"><span class="k">OS</span><span class="v" id="os">—</span></div>
        <div class="row"><span class="k">Kernel</span><span class="v" id="kernel">—</span></div>
        <div class="row"><span class="k">Uptime</span><span class="v" id="uptime">—</span></div>
        <div class="row"><span class="k">CPU(s)</span><span class="v" id="cpus">—</span></div>
      </section>

      <section class="card">
        <h2>Mémoire</h2>
        <div class="row"><span class="k">Total</span><span class="v" id="memTotal">—</span></div>
        <div class="row"><span class="k">Utilisée</span><span class="v" id="memUsed">—</span></div>
      </section>

      <section class="card">
        <h2>Disque</h2>
        <div class="row"><span class="k">Total</span><span class="v" id="diskTotal">—</span></div>
        <div class="row"><span class="k">Libre</span><span class="v" id="diskAvail">—</span></div>
        <div class="line">
          <div class="bar"><span id="diskBar" style="width:0%"></span></div>
        </div>
        <div class="mono" id="partitions">—</div>
      </section>
    </div>

    <section class="card" id="servicesCard" style="display:none">
      <h2>Services actifs</h2>
      <div class="services-list" id="servicesList">
        <div class="service-empty">—</div>
      </div>
    </section>

    <section class="card" id="rawCard" style="display:none">
      <h2>JSON brut</h2>
      <pre class="mono" id="raw">—</pre>
      <div id="error" class="error mono"></div>
    </section>
  </main>
  <div id="tokenOverlay" class="token-overlay">
    <div class="token-dialog">
      <h2>Jeton requis</h2>
      <p>Ce serveur nécessite un jeton pour accéder aux métriques en direct.</p>
      <form id="tokenForm">
        <input id="tokenInput" type="password" placeholder="Jeton d'accès" autocomplete="off" />
        <div class="actions">
          <button type="submit">Valider</button>
          <button type="button" id="tokenForget" class="secondary">Effacer</button>
        </div>
      </form>
      <div id="tokenError" class="token-error" role="alert"></div>
    </div>
  </div>
  <div class="footer">
    Actualisation en direct via SSE (stream fetch) • Pas de framework frontend •
    <button id="tokenOpen" class="link-button" type="button">Modifier le jeton</button>
  </div>

  <script nonce="__CSP_NONCE__">
    const WEB_DEBUG = __WEB_DEBUG__;
    const dot = document.getElementById('statusDot');
    const raw = document.getElementById('raw');
    const err = document.getElementById('error');
    const last = document.getElementById('lastUpdate');
    const rawCard = document.getElementById('rawCard');

    const tokenOverlay = document.getElementById('tokenOverlay');
    const tokenForm = document.getElementById('tokenForm');
    const tokenInput = document.getElementById('tokenInput');
    const tokenErrorEl = document.getElementById('tokenError');
    const tokenForget = document.getElementById('tokenForget');
    const tokenOpen = document.getElementById('tokenOpen');

    const pct = (used, total) => total > 0 ? Math.max(0, Math.min(100, (used/total)*100)) : 0;
    const num = (value) => {
      const n = Number(value);
      return Number.isFinite(n) ? n : 0;
    };

    if (WEB_DEBUG && rawCard) {
      rawCard.style.display = "block";
    }

    const el = (id) => document.getElementById(id);
    const fmtBytes = (n) => {
      const units = ["o","Ko","Mo","Go","To","Po"]; let i = 0, x = Number(n)||0;
      while (x >= 1024 && i < units.length-1) { x /= 1024; i++; }
      return x.toFixed(1) + " " + units[i];
    };
    const fmtSecs = (s) => {
      s = Number(s)||0;
      const d = Math.floor(s/86400); s%=86400;
      const h = Math.floor(s/3600); s%=3600;
      const m = Math.floor(s/60); s%=60;
      const parts = [];
      if (d) parts.push(d+"j"); if (h) parts.push(h+"h"); if (m) parts.push(m+"m"); if (s) parts.push(s+"s");
      return parts.join(" ") || "0s";
    };
    const esc = (value) => {
      const s = value ?? "";
      return String(s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
    };
    const serviceStateClass = (state) => {
      const val = (state || "").toLowerCase();
      if (!val) return "err";
      const okTokens = ["running", "listening", "online", "active"];
      return okTokens.some((token) => val.includes(token)) ? "ok" : "err";
    };

    let currentToken = sessionStorage.getItem('describe_me_token') || "";
    if (currentToken) {
      tokenInput.value = currentToken;
    }
    let abortController = null;
    let reconnectTimer = null;

    tokenForm.addEventListener('submit', (event) => {
      event.preventDefault();
      const value = tokenInput.value.trim();
      if (!value) {
        tokenErrorEl.textContent = "Merci de renseigner un jeton.";
        tokenInput.focus();
        return;
      }
      currentToken = value;
      sessionStorage.setItem('describe_me_token', currentToken);
      hideTokenPrompt();
      restartStream();
    });

    tokenForget.addEventListener('click', () => {
      sessionStorage.removeItem('describe_me_token');
      currentToken = "";
      tokenInput.value = "";
      tokenErrorEl.textContent = "";
      showTokenPrompt("");
    });

    if (tokenOpen) {
      tokenOpen.addEventListener('click', () => {
        tokenInput.value = currentToken;
        tokenErrorEl.textContent = "";
        if (abortController) {
          abortController.abort();
          abortController = null;
        }
        if (reconnectTimer) {
          clearTimeout(reconnectTimer);
          reconnectTimer = null;
        }
        showTokenPrompt("");
      });
    }

    function showTokenPrompt(message) {
      if (typeof message === "string" && message) {
        tokenErrorEl.textContent = message;
      }
      tokenOverlay.classList.add('visible');
      setTimeout(() => tokenInput.focus(), 0);
    }

    function hideTokenPrompt() {
      tokenOverlay.classList.remove('visible');
      tokenErrorEl.textContent = "";
    }

    function restartStream() {
      if (abortController) {
        abortController.abort();
        abortController = null;
      }
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      connectSse();
    }

    async function connectSse() {
      if (abortController) {
        abortController.abort();
      }
      abortController = new AbortController();
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }

      try {
        const headers = {};
        if (currentToken) {
          headers["Authorization"] = `Bearer ${currentToken}`;
        }

        const response = await fetch('/sse', {
          method: 'GET',
          headers,
          signal: abortController.signal,
        });

        if (response.status === 401) {
          const message = await readErrorMessage(response);
          sessionStorage.removeItem('describe_me_token');
          currentToken = "";
          tokenInput.value = "";
          showError(message || "Jeton requis pour accéder aux métriques.");
          showTokenPrompt(message || "Jeton requis pour accéder aux métriques.");
          return;
        }

        if (response.status === 403) {
          const message = await readErrorMessage(response);
          showError(message || "Adresse IP non autorisée.");
          scheduleReconnect();
          return;
        }

        if (!response.ok || !response.body) {
          showError(`Flux SSE indisponible (HTTP ${response.status}).`);
          scheduleReconnect();
          return;
        }

        hideTokenPrompt();
        await consumeSse(response.body);
        abortController = null;
        scheduleReconnect();
      } catch (err) {
        if (err && err.name === 'AbortError') {
          return;
        }
        showError("Flux SSE interrompu (nouvelle tentative dans quelques secondes).");
        scheduleReconnect();
      }
    }

    async function readErrorMessage(response) {
      try {
        const text = await response.text();
        if (!text) return "";
        const data = JSON.parse(text);
        if (data && typeof data.error === "string") {
          return data.error;
        }
        return text;
      } catch (_) {
        return "";
      }
    }

    async function consumeSse(body) {
      const reader = body.getReader();
      const decoder = new TextDecoder('utf-8');
      let buffer = '';

      while (true) {
        const { value, done } = await reader.read();
        if (done) {
          buffer += decoder.decode();
          buffer = processSseBuffer(buffer, true);
          break;
        }
        buffer += decoder.decode(value, { stream: true });
        buffer = processSseBuffer(buffer, false);
      }
    }

    function processSseBuffer(buffer, flush) {
      let index;
      while ((index = buffer.indexOf('\n\n')) !== -1) {
        const chunk = buffer.slice(0, index);
        buffer = buffer.slice(index + 2);
        handleSseEvent(chunk);
      }
      if (flush && buffer.trim() !== "") {
        handleSseEvent(buffer);
        return "";
      }
      return buffer;
    }

    function handleSseEvent(rawEvent) {
      const lines = rawEvent.split(/\r?\n/);
      const dataLines = [];
      for (const line of lines) {
        if (line.startsWith('data:')) {
          dataLines.push(line.slice(5).trimStart());
        }
      }
      if (dataLines.length === 0) {
        return;
      }
      const payload = dataLines.join('\n');
      try {
        const parsed = JSON.parse(payload);
        if (parsed && parsed.error) {
          showError(parsed.error);
          return;
        }
        updateUI(parsed);
      } catch (e) {
        showError("Erreur de parsing JSON: " + (e && e.message ? e.message : e));
      }
    }

    function scheduleReconnect(delay = 4000) {
      if (tokenOverlay.classList.contains('visible')) {
        return;
      }
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
      }
      reconnectTimer = setTimeout(() => {
        reconnectTimer = null;
        connectSse();
      }, delay);
    }

    function updateUI(data) {
      err.textContent = "";

      el('hostname').textContent = data.hostname || "—";
      el('os').textContent = data.os || data.os_name || "—";
      el('kernel').textContent = data.kernel || data.kernel_release || "—";
      el('uptime').textContent = fmtSecs(data.uptime_seconds || 0);
      el('cpus').textContent = data.cpu_count ?? "—";

      el('memTotal').textContent = fmtBytes(data.total_memory_bytes || 0);
      el('memUsed').textContent = fmtBytes(data.used_memory_bytes || 0);

      const du = data.disk_usage || {};
      const total = num(du.total_bytes);
      const avail = num(du.available_bytes);
      let used = du.used_bytes != null ? num(du.used_bytes) : Math.max(0, total - avail);
      if (total > 0 && used > total) {
        used = total;
      }

      el('diskTotal').textContent = fmtBytes(total);
      el('diskAvail').textContent = fmtBytes(avail);
      el('diskBar').style.width = pct(used, total).toFixed(1) + "%";

      const partitions = Array.isArray(du.partitions) ? du.partitions : [];
      const partsHtml = partitions.map(p => {
        const pt = num(p.total_bytes);
        const pa = num(p.available_bytes);
        const usedPart = Math.max(0, Math.min(pt, pt - pa));
        const w = pct(usedPart, pt).toFixed(1) + "%";
        const mp = esc(p.mount_point || "?");
        const fs = esc(p.fs_type || "—");
        return [
          `${mp}  (fs: ${fs}) — total: ${fmtBytes(pt)}, libre: ${fmtBytes(pa)}`,
          `<div class="bar"><span style="width:${w}"></span></div>`
        ].join("\n");
      }).join("\n");

      el('partitions').innerHTML = partsHtml || "—";

      const servicesCard = document.getElementById('servicesCard');
      const servicesList = document.getElementById('servicesList');
      if (servicesCard && servicesList) {
        const services = Array.isArray(data.services_running) ? data.services_running : [];
        const summary = data.services_summary;
        if (services.length > 0) {
          servicesCard.style.display = "block";
          servicesList.innerHTML = services.map((svc) => {
            const name = esc(svc?.name || "Service");
            const stateRaw = svc?.state || "";
            const state = stateRaw ? esc(stateRaw) : "";
            const summaryText = svc?.summary ? esc(svc.summary) : "";
            const dotClass = serviceStateClass(stateRaw);
            const metaParts = [];
            if (state) metaParts.push(state);
            if (summaryText) metaParts.push(summaryText);
            const meta = metaParts.join(" • ");
            return `
              <div class="service-row">
                <span class="dot service-dot ${dotClass}"></span>
                <div>
                  <div class="service-name">${name}</div>
                  ${meta ? `<div class="service-meta">${meta}</div>` : ""}
                </div>
              </div>
            `;
          }).join("");
        } else if (summary && typeof summary.total === 'number') {
          servicesCard.style.display = "block";
          const items = Array.isArray(summary.by_state) ? summary.by_state : [];
          const breakdown = items
            .map(item => `<span class="badge">${item.state}: ${item.count}</span>`)
            .join(" ");
          servicesList.innerHTML = `
            <div class="service-row">
              <span class="dot service-dot"></span>
              <div>
                <div class="service-name">${summary.total} service(s) observé(s)</div>
                <div class="service-meta">${breakdown || "Aucune donnée détaillée"}</div>
              </div>
            </div>
          `;
        } else if ('services_running' in data) {
          servicesCard.style.display = "block";
          servicesList.innerHTML = `<div class="service-empty">Aucun service actif rapporté</div>`;
        } else {
          servicesCard.style.display = "none";
          servicesList.innerHTML = "";
        }
      }

      raw.textContent = JSON.stringify(data, null, 2);
      last.textContent = new Date().toLocaleTimeString();
      dot.classList.add('ok');
    }

    function showError(message) {
      err.textContent = message;
      dot.classList.remove('ok');
    }

    connectSse();
  </script>
</body>
</html>
"#;
