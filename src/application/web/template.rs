use super::assets::MAIN_JS;
use crate::domain::{UpdatePackage, UpdatesInfo};

const INDEX_HTML_TEMPLATE: &str = include_str!("templates/index.html");
const HEADER_SECTION: &str = include_str!("templates/partials/header.html");
const MAIN_LAYOUT_TEMPLATE: &str = include_str!("templates/partials/main_layout.html");
const PRIMARY_GRID: &str = include_str!("templates/partials/primary_grid.html");
const SERVICES_SECTION: &str = include_str!("templates/partials/services.html");
const SOCKETS_SECTION: &str = include_str!("templates/partials/sockets.html");
const RAW_SECTION: &str = include_str!("templates/partials/raw.html");
const TOKEN_OVERLAY: &str = include_str!("templates/partials/token_overlay.html");
const FOOTER_SECTION: &str = include_str!("templates/partials/footer.html");
const INDEX_CSS: &str = concat!(
    include_str!("templates/styles/variables.css"),
    "\n",
    include_str!("templates/styles/base.css"),
    "\n",
    include_str!("templates/styles/grid.css"),
    "\n",
    include_str!("templates/styles/components.css"),
    "\n",
    include_str!("templates/styles/overlays.css"),
    "\n",
    include_str!("templates/styles/animations.css"),
    "\n",
    include_str!("templates/styles/light-theme.css"),
);
const UPDATES_HTML_TEMPLATE: &str = include_str!("templates/updates.html");
const UPDATES_CSS: &str = include_str!("templates/updates.css");

fn fill_template<'a, F>(template: &str, extra_capacity: usize, mut resolver: F) -> String
where
    F: FnMut(&str) -> Option<&'a str>,
{
    let mut out = String::with_capacity(template.len() + extra_capacity);
    let mut remaining = template;

    while let Some(start) = remaining.find("__") {
        out.push_str(&remaining[..start]);
        remaining = &remaining[start + 2..];

        if let Some(end) = remaining.find("__") {
            let key = &remaining[..end];
            remaining = &remaining[end + 2..];
            if let Some(value) = resolver(key) {
                out.push_str(value);
            } else {
                out.push_str("__");
                out.push_str(key);
                out.push_str("__");
            }
        } else {
            out.push_str("__");
            out.push_str(remaining);
            remaining = "";
            break;
        }
    }

    out.push_str(remaining);
    out
}

pub(super) fn render_index(web_debug: bool, csp_nonce: &str) -> String {
    let debug_flag = if web_debug { "true" } else { "false" };
    let main_js = MAIN_JS.replace("__WEB_DEBUG__", debug_flag);
    let main_content = fill_template(
        MAIN_LAYOUT_TEMPLATE,
        PRIMARY_GRID.len() + SERVICES_SECTION.len() + SOCKETS_SECTION.len() + RAW_SECTION.len(),
        |key| match key {
            "PRIMARY_GRID" => Some(PRIMARY_GRID),
            "SERVICES_SECTION" => Some(SERVICES_SECTION),
            "SOCKETS_SECTION" => Some(SOCKETS_SECTION),
            "RAW_SECTION" => Some(RAW_SECTION),
            _ => None,
        },
    );

    let extra_capacity = INDEX_CSS.len()
        + main_js.len()
        + main_content.len()
        + HEADER_SECTION.len()
        + TOKEN_OVERLAY.len()
        + FOOTER_SECTION.len()
        + csp_nonce.len() * 2;

    fill_template(INDEX_HTML_TEMPLATE, extra_capacity, |key| match key {
        "INLINE_CSS" => Some(INDEX_CSS),
        "MAIN_JS" => Some(main_js.as_str()),
        "WEB_DEBUG" => Some(debug_flag),
        "CSP_NONCE" => Some(csp_nonce),
        "HEADER" => Some(HEADER_SECTION),
        "MAIN_CONTENT" => Some(main_content.as_str()),
        "TOKEN_OVERLAY" => Some(TOKEN_OVERLAY),
        "FOOTER" => Some(FOOTER_SECTION),
        _ => None,
    })
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

    let extra_capacity = UPDATES_CSS.len()
        + summary_html.len()
        + details_html.len()
        + message_html.len()
        + csp_nonce.len();

    fill_template(UPDATES_HTML_TEMPLATE, extra_capacity, |key| match key {
        "INLINE_CSS" => Some(UPDATES_CSS),
        "CSP_NONCE" => Some(csp_nonce),
        "SUMMARY" => Some(summary_html.as_str()),
        "DETAILS" => Some(details_html.as_str()),
        "MESSAGE" => Some(message_html.as_str()),
        _ => None,
    })
}

#[allow(dead_code)]
fn render_update_howto(_updates: Option<&UpdatesInfo>) -> String {
    // Detect distribution via /etc/os-release; fallback to generic commands.
    let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let lower = os_release.to_ascii_lowercase();

    // List-only commands per distro (no upgrade)
    let (title, commands): (&str, &str) =
        if lower.contains("id=arch") || lower.contains("id_like=arch") {
            ("Arch Linux", "pacman -Qu\n# ou: checkupdates\n")
        } else if lower.contains("id=alpine") || lower.contains("id_like=alpine") {
            (
                "Alpine Linux",
                "apk list -u\n# ou: apk upgrade -s --available\n",
            )
        } else if lower.contains("id=fedora")
            || lower.contains("id_like=fedora")
            || lower.contains("id=rocky")
            || lower.contains("id=almalinux")
            || lower.contains("id=rhel")
            || lower.contains("id_like=rhel")
        {
            (
                "Fedora/RHEL (dnf)",
                "dnf -q check-update\n# ou: dnf update --assumeno\n",
            )
        } else if lower.contains("id=debian")
            || lower.contains("id_like=debian")
            || lower.contains("id=ubuntu")
            || lower.contains("id_like=ubuntu")
        {
            (
                "Debian/Ubuntu (apt)",
                "apt list --upgradable\n# ou (simulation): apt-get -s upgrade\n",
            )
        } else {
            (
                "Mise à jour système",
                "# Exemple (dnf)\ndnf -q check-update\n# Exemple (apt)\napt list --upgradable\n",
            )
        };

    format!(
        r#"<p class="muted">Exécuter ces commandes en SSH avec un compte administrateur.</p>
<div style="background:#0b0e16;border:1px solid #222838;border-radius:8px;padding:12px">
  <div style="color:#a8b3c3;font-size:13px;margin-bottom:6px">{title}</div>
  <pre style="margin:0;color:#e6eef8"><code>{commands}</code></pre>
</div>"#,
        title = escape_html(title),
        commands = commands,
    )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fill_template_replaces_known_and_preserves_unknown() {
        let template = "Hello __NAME__! __UNKNOWN__";
        let result = fill_template(template, 4, |key| match key {
            "NAME" => Some("World"),
            _ => None,
        });
        assert_eq!(result, "Hello World! __UNKNOWN__");
    }

    #[test]
    fn fill_template_handles_unterminated_placeholder() {
        let template = "Start __OPEN";
        let result = fill_template(template, 0, |_| None);
        assert_eq!(result, "Start __OPEN");
    }

    #[test]
    fn render_index_injects_dynamic_values() {
        let html = render_index(true, "nonce-value");
        assert!(html.contains("nonce=\"nonce-value\""));
        assert!(html.contains("const WEB_DEBUG = true;") || html.contains(">true<"));
        assert!(!html.contains("__CSP_NONCE__"));
        assert!(!html.contains("__INLINE_CSS__"));
        assert!(html.contains("src=\"/assets/logo.svg\""));
        assert!(html.contains("class=\"brand-title\""));
    }

    #[test]
    fn render_updates_page_renders_sections() {
        let info = UpdatesInfo {
            pending: 2,
            reboot_required: false,
            packages: None,
        };
        let html = render_updates_page(Some(&info), Some("Attention"), "nonce");
        assert!(html.contains("stat-value\">2</div>"));
        assert!(html.contains("Attention"));
        assert!(!html.contains("__SUMMARY__"));
        assert!(!html.contains("__INLINE_CSS__"));
    }

    #[test]
    fn escape_html_blocks_tags() {
        assert_eq!(escape_html("<img onerror=1>"), "&lt;img onerror=1&gt;");
    }
}
