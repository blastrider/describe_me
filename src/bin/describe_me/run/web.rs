use anyhow::{bail, Result};
#[cfg(feature = "config")]
use describe_me_lib::domain::DescribeConfig;
use describe_me_lib::{WebAccess, WebTlsConfig};
#[cfg(not(feature = "config"))]
type DescribeConfig = ();

use crate::describe_me::allowlists::resolve_web_list;
use crate::describe_me::args::CliConfig;
use crate::describe_me::exposure::apply_web_exposure_flags;

use super::config::WebListOrigins;

pub fn build_web_access(
    cli: &CliConfig,
    cfg: Option<&DescribeConfig>,
    origins: &WebListOrigins,
) -> WebAccess {
    let mut web_access = WebAccess::default();

    let (config_allow_ips, config_allow_origins, config_trusted_proxies) = {
        #[cfg(feature = "config")]
        {
            let web_cfg = cfg.and_then(|cfg| cfg.web.as_ref());
            if let Some(web_cfg) = web_cfg {
                if let Some(token) = web_cfg.token.as_ref() {
                    web_access.token = Some(token.clone());
                }
                if let Some(tls_cfg) = web_cfg.tls.as_ref() {
                    if !tls_cfg.cert_path.is_empty() && !tls_cfg.key_path.is_empty() {
                        web_access.tls = Some(WebTlsConfig {
                            cert_path: tls_cfg.cert_path.clone(),
                            key_path: tls_cfg.key_path.clone(),
                        });
                    }
                }
                if web_cfg.dev_insecure_session_cookie {
                    web_access.session_cookie_secure = false;
                }
            }
            (
                web_cfg.map(|cfg| cfg.allow_ips.as_slice()),
                web_cfg.map(|cfg| cfg.allow_origins.as_slice()),
                web_cfg.map(|cfg| cfg.trusted_proxies.as_slice()),
            )
        }
        #[cfg(not(feature = "config"))]
        {
            let _ = cfg;
            (None, None, None)
        }
    };

    if let Some(token) = &cli.web.token {
        web_access.token = Some(token.clone());
    }

    // Precedence is: CLI > config > runtime defaults.
    web_access.allow_ips = resolve_web_list(
        origins.allow_ip().cli_slice(&cli.web.allow_ip),
        config_allow_ips,
        origins.allow_ip().runtime_slice(&cli.web.allow_ip),
    );
    web_access.allow_origins = resolve_web_list(
        origins.allow_origin().cli_slice(&cli.web.allow_origin),
        config_allow_origins,
        origins.allow_origin().runtime_slice(&cli.web.allow_origin),
    );
    web_access.trusted_proxies = resolve_web_list(
        origins.trusted_proxy().cli_slice(&cli.web.trusted_proxy),
        config_trusted_proxies,
        origins
            .trusted_proxy()
            .runtime_slice(&cli.web.trusted_proxy),
    );

    if cli.web.dev_mode {
        web_access.session_cookie_secure = false;
    }

    web_access
}

pub fn build_web_exposure(
    exposure: describe_me_lib::Exposure,
    cli: &CliConfig,
    cfg: Option<&DescribeConfig>,
    allow_config_exposure: bool,
) -> describe_me_lib::Exposure {
    #[cfg(feature = "config")]
    {
        apply_web_exposure_flags(exposure, cli, cfg, allow_config_exposure)
    }
    #[cfg(not(feature = "config"))]
    {
        let _ = cfg;
        apply_web_exposure_flags(exposure, cli, allow_config_exposure)
    }
}

pub fn start_web_server(
    bind: &str,
    interval_secs: u64,
    web_access: WebAccess,
    web_exposure: describe_me_lib::Exposure,
    cfg: Option<DescribeConfig>,
    web_debug: bool,
    ctx: describe_me_lib::AppContext,
) -> Result<()> {
    use std::net::SocketAddr;
    #[cfg(not(feature = "config"))]
    let _ = cfg;

    let addr: SocketAddr = bind
        .parse()
        .map_err(|e| anyhow::anyhow!("Adresse invalide pour --web: {bind} ({e})"))?;
    let tick = std::time::Duration::from_secs(interval_secs);

    if web_access.token.is_none() && web_access.allow_ips.is_empty() {
        bail!(
            "--web nécessite la configuration d'un contrôle d'accès (--web-token, --web-allow-ip ou [web] dans la config)."
        );
    }

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(async move {
        describe_me_lib::serve_http_with_context(
            addr,
            tick,
            #[cfg(feature = "config")]
            cfg,
            web_debug,
            web_access,
            web_exposure,
            ctx,
        )
        .await
    })?;
    Ok(())
}

#[cfg(all(test, feature = "config"))]
mod tests {
    use super::*;
    use crate::describe_me::args;
    use clap::Parser;

    fn base_cli() -> CliConfig {
        args::Opts::parse_from(["describe-me"]).into()
    }

    #[test]
    fn web_access_prefers_cli_over_config_and_runtime_defaults() {
        let mut cli = base_cli();
        cli.web.allow_ip = vec!["192.0.2.10".into()];
        cli.web.allow_origin = vec!["https://cli.example.com".into()];
        cli.web.trusted_proxy = vec!["10.0.0.0/8".into()];

        let cfg = DescribeConfig {
            web: Some(describe_me_lib::domain::WebAccessConfig {
                allow_ips: vec!["10.0.0.1".into()],
                allow_origins: vec!["https://config.example.com".into()],
                trusted_proxies: vec!["192.0.2.0/24".into()],
                ..Default::default()
            }),
            ..Default::default()
        };

        let origins = WebListOrigins::from_cli(&cli);

        let access = build_web_access(&cli, Some(&cfg), &origins);
        assert_eq!(access.allow_ips, vec!["192.0.2.10".to_string()]);
        assert_eq!(
            access.allow_origins,
            vec!["https://cli.example.com".to_string()]
        );
        assert_eq!(access.trusted_proxies, vec!["10.0.0.0/8".to_string()]);
    }

    #[test]
    fn web_access_prefers_config_over_runtime_defaults() {
        let cli = base_cli();
        let cfg = DescribeConfig {
            web: Some(describe_me_lib::domain::WebAccessConfig {
                allow_ips: vec!["10.0.0.1".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let mut origins = WebListOrigins::from_cli(&cli);
        origins.mark_allow_ip_runtime_default();

        let access = build_web_access(&cli, Some(&cfg), &origins);
        assert_eq!(access.allow_ips, vec!["10.0.0.1".to_string()]);
    }

    #[test]
    fn web_access_uses_runtime_defaults_when_cli_and_config_missing() {
        let mut cli = base_cli();
        cli.web.allow_ip = vec!["203.0.113.1".into()];
        cli.web.allow_origin = vec!["https://runtime.example.com".into()];
        cli.web.trusted_proxy = vec!["198.51.100.0/24".into()];

        let mut origins = WebListOrigins::from_cli(&cli);
        origins.mark_allow_ip_runtime_default();
        origins.mark_allow_origin_runtime_default();
        origins.mark_trusted_proxy_runtime_default();

        let access = build_web_access(&cli, None, &origins);
        assert_eq!(access.allow_ips, vec!["203.0.113.1".to_string()]);
        assert_eq!(
            access.allow_origins,
            vec!["https://runtime.example.com".to_string()]
        );
        assert_eq!(access.trusted_proxies, vec!["198.51.100.0/24".to_string()]);
    }
}
