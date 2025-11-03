# CLI `describe-me`

Le binaire est activé par la feature `cli` et vit dans
`src/bin/describe-me.rs`. Il combine capture de snapshot, health checks,
inventaire réseau et serveur web SSE.

## Options principales

| Option                      | Effet                                                       |
|-----------------------------|-------------------------------------------------------------|
| `--with-services`           | Inclut les services systemd (feature `systemd`)             |
| `--disks`                   | Force le calcul des partitions dans la sortie CLI           |
| `--net-listen`              | Affiche les sockets TCP/UDP (feature `net`) et les ajoute à `SnapshotView` |
| `--process`                 | Affiche le PID propriétaire (requiert `--net-listen`)       |
| `--json` / `--pretty`       | Sortie JSON brute/indentée                                  |
| `--summary`                 | Ajoute une ligne de résumé (`updates=<N> reboot=<yes|no|unknown>`) |
| `--check <expr>`            | Health checks (`mem`, `disk`, `service`)                    |
| `--web[=ADDR:PORT]`         | Lance le serveur SSE intégré (feature `web`)                |
| `--web-token`, `--web-allow-ip` | Sécurisation du mode web (hash Argon2id/bcrypt + allowlist IP, voir `docs/web-security.md`) |
| `--hash-web-token`, `--hash-web-token-stdin` | Helper pour générer une empreinte (Argon2id par défaut) |
| `--expose-*`, `--no-redacted`, `--expose-all` | Contrôle fin des champs sensibles (hostname, services, partitions, sockets, updates) |
| `--web-expose-*`, `--web-expose-all` | Variante pour l’interface SSE                      |

La CLI refuse explicitement de tourner en root (`ensure_not_root`).

## Configuration TOML

Si la feature `config` est activée, `--config <path>` permet de charger
un fichier TOML (`DescribeConfig`). Il peut définir :

- Valeurs par défaut CLI (`runtime.cli`).
- Filtrage des services (`services.include`).
- Paramètres SSE (`web.security`, `web.allow_ips`, `web.exposure`).
- Exposition JSON (`exposure`, y compris `expose_updates` pour la tuile des mises à jour).

> **Note :** `web.token` attend désormais une empreinte Argon2id/bcrypt. Utilisez
> `describe-me --hash-web-token 'secret'` pour produire une valeur compatible.

Les erreurs de lecture/parsing sont remontées par `DescribeError::Config`
et journalisées (`LogEvent::ConfigError`).

## Sortie combinée

Le mode CLI assemble :

- `SnapshotView` (exposition/redaction configurables).
- Optionnellement, les sockets (`net_listen`).
- Des messages de health check (stderr) avec code de sortie 0/1/2.
- Si `--summary` est présent, une ligne courte est affichée avant toute autre
  sortie. Elle inclut notamment `updates=<N>` et `reboot=<yes|no|unknown>`, puis
  les sorties habituelles (tableaux, JSON, etc.) sont produites.

Le serveur web réutilise ces mêmes structures, cadencées par `tokio` et
l’intervalle `--web-interval`.
