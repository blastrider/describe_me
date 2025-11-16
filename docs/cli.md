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
| `--expose-extensions`, `--web-expose-extensions` | Active l’exposition des résultats des plugins (CLI / mode web) |
| `--web-expose-*`, `--web-expose-all` | Variante pour l’interface SSE                      |

La CLI refuse explicitement de tourner en root (`ensure_not_root`).

## Configuration TOML

Si la feature `config` est activée, `--config <path>` permet de charger
un fichier TOML (`DescribeConfig`). Il peut définir :

- Valeurs par défaut CLI (`runtime.cli`).
- Filtrage des services (`services.include`).
- Paramètres SSE (`web.security`, `web.allow_ips`, `web.exposure`).
- Exposition JSON (`exposure`, y compris `expose_updates` pour la tuile des mises à jour).
- Extensions/collecteurs externes (`extensions.plugins`, `exposure.expose_extensions`, `web.exposure.expose_extensions`).

> **Note :** `web.token` attend désormais une empreinte Argon2id/bcrypt. Utilisez
> `describe-me --hash-web-token 'secret'` pour produire une valeur compatible.
> Les listes `web.allow_ips`, `web.allow_origins` et `web.trusted_proxies` ne
> sont pas fusionnées : une valeur CLI (`--web-*`) prime sur `[web]`, elle-même
> prioritaire sur `[runtime.cli]`. Un réglage donné n'agit donc qu'à l'endroit
> où il est défini.

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
- Lorsque la description est définie, une section `Description : ...` est
  imprimée avant les tableaux, et le champ `server_description` est inclus
  dans le JSON/SSE.

Le serveur web réutilise ces mêmes structures, cadencées par `tokio` et
l’intervalle `--web-interval`.

## Métadonnées persistées (redb)

Le binaire embarque maintenant un mini-stockage redb (`metadata.redb`) pour
retenir une description libre du serveur (rôle, contexte, contacts). La CLI
expose une sous-commande dédiée :

```
describe-me metadata description show
describe-me metadata description set "Serveur FTP staging (contact: infra@example.com)"
describe-me metadata description clear
```

- `set` crée ou remplace la description.
- `show` affiche la valeur brute ou indique l’absence de donnée.
- `clear` supprime l’entrée.

Le fichier est écrit dans `DESCRIBE_ME_STATE_DIR` s’il est défini, sinon dans
`STATE_DIRECTORY` (systemd) ou, à défaut, dans les emplacements XDG/`LOCALAPPDATA`.
Il est désormais possible de forcer explicitement ce répertoire via le fichier
de configuration : ajoutez `state_dir = "/var/lib/describe-me"` dans la section
`[runtime]` (ex. `config_tls.toml`) et toutes les commandes CLI/Web utiliseront
ce chemin pour `metadata.redb`.
Les snapshots (CLI, JSON, SSE) réutilisent automatiquement ce contenu et l’interface web
affiche un bloc « Description » modifiable (formulaire avec sauvegarde immédiate via `POST /api/description`).

Les tags serveur sont gérés via la même sous-commande :

```
describe-me metadata tags show
describe-me metadata tags set ubuntu ftp prod
describe-me metadata tags add staging europe
describe-me metadata tags remove prod
describe-me metadata tags clear
```

Les tags sont normalisés (minuscules, tirets) et affichés dans la sortie CLI ainsi
que dans l’interface web pour faciliter le regroupement des machines. Le tableau
de bord web dispose également d’un champ « Tags » pour ajouter/supprimer/vider la
liste directement depuis le navigateur (mêmes validations côté API).

## Plugins externes

- Créez un plugin via la crate `describe_me_plugin_sdk` (trait `Plugin`, type `PluginOutput`, macro `describe_me_plugin_main!`) puis exécutez-le à la demande avec `describe-me plugin run --cmd /chemin/vers/plugin --arg foo --timeout 5`.
- Listez des plugins à exécuter automatiquement en ajoutant :

```toml
[extensions]
[[extensions.plugins]]
name = "certificates-demo"
cmd = "/usr/bin/describe-me-plugin-certificates"
args = ["--probe", "/etc/ssl/certs", "--probe", "/etc/describe_me/certs"]
timeout_secs = 10
```

Chaque plugin est exécuté séquentiellement avec un timeout configurable. La sortie JSON est désérialisée dans `PluginOutput` et publiée sous `extensions.<nom>` dans `SnapshotView`, l’API et l’UI web (activer `expose_extensions`/`web_expose_extensions` pour rendre les données visibles). Les erreurs sont loguées (`LogEvent::PluginError`) mais n’interrompent pas la capture principale.
