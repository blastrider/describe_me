use super::assets::MAIN_JS;

pub(super) fn render_index(web_debug: bool, csp_nonce: &str) -> String {
    INDEX_HTML
        .replace("__MAIN_JS__", MAIN_JS)
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
    .status-ok { color: var(--ok); }
    .status-warn { color: var(--warn); }
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

      <section class="card" id="updatesCard" style="display:none">
        <h2>Mises à jour</h2>
        <div class="row"><span class="k">En attente</span><span class="v" id="updatesPending">—</span></div>
        <div class="row"><span class="k">Redémarrage</span><span class="v" id="updatesReboot">—</span></div>
        <div class="row"><span class="k">Statut</span><span class="v" id="updatesStatus">—</span></div>
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

      <section class="card" id="networkCard" style="display:none">
        <h2>Trafic reseau</h2>
        <div class="services-list" id="networkList">
          <div class="service-empty">—</div>
        </div>
      </section>
    </div>

    <section class="card" id="servicesCard" style="display:none">
      <h2>Services actifs</h2>
      <div class="services-list" id="servicesList">
        <div class="service-empty">—</div>
      </div>
    </section>

    <div class="grid" id="socketsGrid" style="display:none">
      <section class="card" id="socketsTcpCard">
        <h2>Ports TCP en écoute</h2>
        <div class="services-list" id="socketsTcp">
          <div class="service-empty">—</div>
        </div>
      </section>
      <section class="card" id="socketsUdpCard">
        <h2>Ports UDP en écoute</h2>
        <div class="services-list" id="socketsUdp">
          <div class="service-empty">—</div>
        </div>
      </section>
    </div>

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
__MAIN_JS__
  </script>
</body>
</html>
"#;
