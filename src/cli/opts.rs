use clap::{ArgAction, Parser};
use std::net::SocketAddr;
use std::path::PathBuf;

const WEB_INTERVAL_MIN: u64 = 1;
const WEB_INTERVAL_MAX: u64 = 3600;

#[derive(Parser, Debug)]
#[command(name = "describe-me", version, about = "Décrit rapidement le serveur")]
pub(crate) struct Opts {
    /// Énumérer aussi les services (Linux/systemd)
    #[arg(long)]
    pub(crate) with_services: bool,

    /// Afficher l'usage disque (agrégé + partitions)
    #[arg(long)]
    pub(crate) disks: bool,

    /// Fichier de config TOML (feature `config`)
    #[arg(long, value_name = "FILE")]
    pub(crate) config: Option<PathBuf>,

    /// Autorise que --config soit un lien symbolique (par défaut: refusé)
    #[arg(long = "config-allow-symlink", action = ArgAction::SetTrue)]
    pub(crate) config_allow_symlink: bool,

    /// Autorise que --config soit en dehors des répertoires approuvés (voir doc)
    #[arg(long = "config-allow-outside", action = ArgAction::SetTrue)]
    pub(crate) config_allow_outside: bool,

    /// Affiche les sockets d’écoute (TCP/UDP) — nécessite la feature `net`
    #[arg(long = "net-listen", action = ArgAction::SetTrue)]
    pub(crate) net_listen: bool,

    /// Affiche aussi le PID propriétaire (si résolu) — nécessite `--net-listen`
    #[arg(long = "process", requires = "net_listen", action = ArgAction::SetTrue)]
    pub(crate) show_process: bool,

    /// Force la sortie 100% JSON (un seul document)
    #[arg(long, action = ArgAction::SetTrue)]
    pub(crate) json: bool,

    /// Mise en forme JSON indentée (implique --json)
    #[arg(long, action = ArgAction::SetTrue, requires = "json")]
    pub(crate) pretty: bool,

    /// Mode sécurité renforcée (refuse exposition réseau non locale, durcit defaults)
    #[arg(long = "safe-defaults", action = ArgAction::SetTrue)]
    pub(crate) safe_defaults: bool,

    /// Lance un serveur web SSE — nécessite la feature `web`.
    /// Adresse:port optionnelle (défaut sécurisé: 127.0.0.1:8080)
    #[arg(
        long = "web",
        value_name = "ADDR:PORT",
        default_missing_value = "127.0.0.1:8080",
        num_args = 0..=1,
        value_parser = clap::value_parser!(SocketAddr)
    )]
    pub(crate) web: Option<SocketAddr>,

    /// Autorise l’écoute réseau non locale (ex: 0.0.0.0). Sans ça, refus explicite.
    #[arg(long = "web-allow-remote", action = ArgAction::SetTrue)]
    pub(crate) web_allow_remote: bool,

    /// Intervalle d'actualisation (secondes) pour --web (défaut: 2, bornes 1..=3600)
    #[arg(
        long = "web-interval",
        value_name = "SECS",
        default_value_t = 2,
        value_parser = clap::value_parser!(u64).range(WEB_INTERVAL_MIN..=WEB_INTERVAL_MAX)
    )]
    pub(crate) web_interval_secs: u64,

    /// Affiche également le JSON brut dans l'interface --web
    #[arg(long = "web-debug", action = ArgAction::SetTrue)]
    pub(crate) web_debug: bool,
}
