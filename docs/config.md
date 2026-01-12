# Configuration

Ce document resume ou trouver les fichiers de configuration du repo, comment les
charger et ou verifier les options disponibles.

## Fichiers de configuration fournis dans le repo

- `docs/config.reference.toml` — gabarit complet commente (toutes options).
- `packaging/config/config.toml` — profil Debian/HTTPS (prod, installe sous `/etc/describe_me/config.toml`).
- `docker/config.dev.toml` — config dev HTTP (compose).
- `config.local.toml` — config dev local hors conteneur.

## Emplacements documentes

- Debian : `/etc/describe_me/config.toml` (source `packaging/config/config.toml`).
- FreeBSD : `/usr/local/etc/describe_me/config.toml` (source `packaging/freebsd/README.md`).

## Chargement

- `--config <path>` charge un fichier TOML quand la feature `config` est activee.
  Reference : `docs/cli.md`.
- Auto-decouverte d'un fichier de configuration : a completer.

## Precedence

- Pour `web.allow_ips`, `web.allow_origins`, `web.trusted_proxies` :
  CLI `--web-*` > `[web]` > `[runtime.cli]` (valeurs non fusionnees).
  Reference : `docs/cli.md` + `docs/utilisateurs/guide.md`.
- Autres options : a completer (comportement exact a documenter si exceptions).

## Reference complete

- Toutes les options et leurs commentaires : `docs/config.reference.toml`.
