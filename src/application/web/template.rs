use super::assets::MAIN_JS;
use crate::domain::{UpdatePackage, UpdatesInfo};

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
    .card-actions {
      display: flex;
      gap: 8px;
      align-items: center;
    }
    .card-actions .link-button {
      text-decoration: none;
    }
    .card-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
    }
    .card-header h2 { margin: 0; }
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
    .link-button.small { font-size: 13px; color: var(--muted); }
    .link-button.small:hover { color: var(--text); }
    @media (prefers-color-scheme: light) {
      :root { --bg:#f6f7fb; --card:#ffffff; --text:#1d2330; --muted:#5b667a; }
      body { background: var(--bg); color: var(--text); }
      .card { border-color: #e4e8f1; }
    }
     .bar { position: relative; height: 10px; background: #1d2333; border:1px solid #2a3147; border-radius:6px; overflow:hidden; }
     .bar > span { position:absolute; left:0; top:0; bottom:0; background:#3ad29f55; border-right:2px solid #3ad29f; }
     .mono .line { margin: 6px 0 10px; }
    .services-list { display: flex; flex-direction: column; gap: 10px; }
    #networkCard { grid-column: 1 / -1; }
    .network-grid {
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(auto-fit, minmax(260px, 1fr));
    }
    .network-grid .service-row { height: 100%; }
    .network-grid .service-empty {
      grid-column: 1 / -1;
      text-align: center;
    }
    .service-row {
      display: flex; align-items: flex-start; gap: 10px;
      padding: 8px 10px; border-radius: 8px; background: #1d2333; border: 1px solid #2a3147;
    }
    .service-row > div { flex: 1 1 auto; min-width: 0; }
    .service-dot { margin-top: 4px; }
    .service-name { font-weight: 600; }
    .service-meta { margin-top: 2px; font-size: 13px; color: var(--muted); word-break: break-word; }
    .service-empty { color: var(--muted); font-style: italic; }
    #rawBody { margin-top: 10px; }
    #rawBody.collapsed { display: none; }
    .updates-details { margin-top: 12px; }
    .updates-details.collapsed { display: none; }
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
        <div class="card-header">
          <h2>Mises à jour</h2>
          <div class="card-actions">
            <a href="/updates" class="link-button small" id="updatesDetailsPage">Page dédiée</a>
            <button type="button" id="updatesDetailsToggle" class="link-button small" style="display:none">Détails</button>
          </div>
        </div>
        <div class="row"><span class="k">En attente</span><span class="v" id="updatesPending">—</span></div>
        <div class="row"><span class="k">Redémarrage</span><span class="v" id="updatesReboot">—</span></div>
        <div class="row"><span class="k">Statut</span><span class="v" id="updatesStatus">—</span></div>
        <div class="updates-details collapsed" id="updatesDetails">
          <div class="services-list updates-list" id="updatesList">
            <div class="service-empty">—</div>
          </div>
        </div>
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
        <div class="network-grid" id="networkList">
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
      <div class="card-header">
        <h2>JSON brut</h2>
        <button type="button" id="rawToggle" class="link-button small">Masquer</button>
      </div>
      <div id="rawBody">
        <pre class="mono" id="raw">—</pre>
        <div id="error" class="error mono"></div>
      </div>
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

const UPDATES_HTML: &str = r#"<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta
    name="viewport"
    content="width=device-width, initial-scale=1, viewport-fit=cover">
  <title>describe_me — Détails des mises à jour</title>
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
    body {
      margin: 0; background: var(--bg); color: var(--text);
      font-family: system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    header {
      padding: 18px 24px; border-bottom: 1px solid #222838;
      display: flex; justify-content: space-between; align-items: center;
    }
    main { flex: 1 1 auto; padding: 24px; max-width: 900px; margin: 0 auto; display: grid; gap: 18px; }
    h1 { margin: 0; font-size: 20px; }
    h2 { margin: 0 0 12px; font-size: 18px; color: var(--muted); }
    .card {
      background: var(--card); border: 1px solid #222838; border-radius: 10px;
      padding: 20px; box-shadow: 0 4px 12px rgba(0,0,0,.25);
    }
    .stats-grid {
      display: grid; gap: 14px;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
    }
    .stat-label { color: var(--muted); font-size: 13px; text-transform: uppercase; letter-spacing: .05em; }
    .stat-value { font-size: 24px; font-weight: 600; font-family: var(--mono); }
    .status-ok { color: var(--ok); }
    .status-warn { color: var(--warn); }
    .updates-list { display: flex; flex-direction: column; gap: 10px; }
    .service-row {
      display: flex; align-items: flex-start; gap: 10px;
      padding: 10px 12px; border-radius: 8px; background: #1d2333; border: 1px solid #2a3147;
    }
    .service-dot { margin-top: 5px; width: 8px; height: 8px; border-radius: 999px; background: var(--warn); box-shadow: 0 0 6px var(--warn); }
    .service-name { font-weight: 600; }
    .service-meta { margin-top: 2px; font-size: 13px; color: var(--muted); word-break: break-word; }
    .service-empty { color: var(--muted); font-style: italic; }
    .notice {
      border-left: 3px solid var(--warn);
      background: rgba(255, 209, 102, 0.08);
      padding: 12px 16px;
      border-radius: 6px;
      color: var(--warn);
    }
    .link-button {
      background: none; border: none; color: inherit; font: inherit;
      text-decoration: underline; cursor: pointer; padding: 0;
    }
    .link-button:hover { text-decoration: none; }
    .link-button.small { font-size: 13px; color: var(--muted); }
    .link-button.small:hover { color: var(--text); }
    .muted { color: var(--muted); }
    .footer { padding: 18px 24px 24px; text-align: center; color: var(--muted); font-size: 13px; }
    @media (prefers-color-scheme: light) {
      :root { --bg:#f6f7fb; --card:#ffffff; --text:#1d2330; --muted:#5b667a; }
      body { background: var(--bg); color: var(--text); }
      header { border-color: #dce1ef; }
      .card { border-color: #dce1ef; box-shadow: 0 4px 12px rgba(0,0,0,.15); }
      .service-row { background: #f0f2fb; border-color: #d6dbeb; }
      .service-dot { background: #ffd166; box-shadow: 0 0 6px #ffd166; }
    }
  </style>
</head>
<body>
  <header>
    <h1>Détails des mises à jour</h1>
    <a class="link-button" href="/">← Retour au tableau de bord</a>
  </header>
  <main>
    __MESSAGE__
    <section class="card">
      <h2>Résumé</h2>
      __SUMMARY__
    </section>
    <section class="card">
      <h2>Liste des paquets</h2>
      __DETAILS__
    </section>
  </main>
  <div class="footer">describe_me • affichage ponctuel (pas d'auto-refresh)</div>
</body>
</html>
"#;

pub(super) fn render_updates_page(
    updates: Option<&UpdatesInfo>,
    message: Option<&str>,
    csp_nonce: &str,
) -> String {
    let summary_html = render_updates_summary(updates);
    let details_html = render_updates_details(updates);
    let message_html = message
        .map(|msg| format!("<div class=\"notice\">{}</div>", escape_html(msg)))
        .unwrap_or_default();

    UPDATES_HTML
        .replace("__CSP_NONCE__", csp_nonce)
        .replace("__SUMMARY__", &summary_html)
        .replace("__DETAILS__", &details_html)
        .replace("__MESSAGE__", &message_html)
}

fn render_updates_summary(updates: Option<&UpdatesInfo>) -> String {
    if let Some(info) = updates {
        let pending = info.pending;
        let reboot = if info.reboot_required { "Oui" } else { "Non" };
        let (status_text, status_class) = if pending == 0 && !info.reboot_required {
            ("À jour", "status-ok")
        } else if info.reboot_required {
            ("Redémarrage requis", "status-warn")
        } else {
            ("Mises à jour disponibles", "status-warn")
        };

        format!(
            r#"<div class="stats-grid">
                <div><div class="stat-label">En attente</div><div class="stat-value">{pending}</div></div>
                <div><div class="stat-label">Redémarrage</div><div class="stat-value">{reboot}</div></div>
                <div><div class="stat-label">Statut</div><div class="stat-value {status_class}">{status_text}</div></div>
              </div>"#
        )
    } else {
        "<p class=\"muted\">Les informations de mise à jour ne sont pas disponibles.</p>".into()
    }
}

fn render_updates_details(updates: Option<&UpdatesInfo>) -> String {
    if let Some(info) = updates {
        if let Some(packages) = info.packages.as_ref().map(|slice| slice.as_slice()) {
            if packages.is_empty() {
                return "<p class=\"muted\">Aucune mise à jour détaillée n'est disponible.</p>"
                    .into();
            }
            let mut out = String::with_capacity(packages.len() * 80);
            for pkg in packages {
                out.push_str(&render_package_entry(pkg));
            }
            format!("<div class=\"updates-list\">{out}</div>")
        } else {
            "<p class=\"muted\">La liste détaillée n'est pas fournie par le collecteur.</p>".into()
        }
    } else {
        "<p class=\"muted\">Aucune donnée n'a été transmise.</p>".into()
    }
}

fn render_package_entry(pkg: &UpdatePackage) -> String {
    let name = escape_html(&pkg.name);
    let mut meta_parts: Vec<String> = Vec::new();
    if let (Some(current), Some(available)) = (&pkg.current_version, &pkg.available_version) {
        meta_parts.push(format!(
            "{} → {}",
            escape_html(current),
            escape_html(available)
        ));
    } else if let Some(available) = &pkg.available_version {
        meta_parts.push(format!("Version : {}", escape_html(available)));
    } else if let Some(current) = &pkg.current_version {
        meta_parts.push(format!("Installée : {}", escape_html(current)));
    }
    if let Some(repo) = &pkg.repository {
        meta_parts.push(escape_html(repo));
    }
    let meta_html = if meta_parts.is_empty() {
        String::new()
    } else {
        format!(
            "<div class=\"service-meta\">{}</div>",
            meta_parts.join(" • ")
        )
    };

    format!(
        r#"<div class="service-row">
              <span class="dot service-dot"></span>
              <div>
                <div class="service-name">{name}</div>
                {meta_html}
              </div>
            </div>"#
    )
}

fn escape_html(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            _ => escaped.push(ch),
        }
    }
    escaped
}
