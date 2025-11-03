use super::assets::MAIN_JS;
use crate::domain::{UpdatePackage, UpdatesInfo};

const INDEX_HTML_TEMPLATE: &str = include_str!("templates/index.html");
const INDEX_CSS: &str = include_str!("templates/index.css");
const UPDATES_HTML_TEMPLATE: &str = include_str!("templates/updates.html");
const UPDATES_CSS: &str = include_str!("templates/updates.css");

pub(super) fn render_index(web_debug: bool, csp_nonce: &str) -> String {
    let debug_flag = if web_debug { "true" } else { "false" };
    INDEX_HTML_TEMPLATE
        .replace("__INLINE_CSS__", INDEX_CSS)
        .replace("__MAIN_JS__", MAIN_JS)
        .replace("__WEB_DEBUG__", debug_flag)
        .replace("__CSP_NONCE__", csp_nonce)
}

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

    UPDATES_HTML_TEMPLATE
        .replace("__INLINE_CSS__", UPDATES_CSS)
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
