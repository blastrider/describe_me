# Développer un plugin « describe_me »

Ce guide explique comment construire un nouveau collecteur externe (« module ») pour `describe_me` à l’aide de la crate `describe_me_plugin_sdk`, comment le tester via la CLI et comment le déclarer côté configuration.

## 1. Préparer la crate

```toml
[package]
name = "describe-me-plugin-inventory"
edition = "2021"

[dependencies]
describe_me_plugin_sdk = { path = "../describe_me_plugin_sdk" } # ou depuis crates.io
```

## 2. Exemple Rust minimal

```rust
use describe_me_plugin_sdk::{run_plugin, PluginConfig, PluginOutput, PluginResult};

fn main() {
    let config = PluginConfig::new("inventory")
        .with_error_prefix("describe-me-plugin-inventory");

    run_plugin(config, |_ctx| {
        // LaunchContext validé (env DESCRIBE_ME_*); utiliser `_ctx` si besoin.
        Ok(PluginOutput::new().with("status", "ok"))
    });
}
```

`run_plugin` lit et valide le *LaunchContext* (`DESCRIBE_ME_HOST`,
`DESCRIBE_ME_PLUGIN_NAME`, `DESCRIBE_ME_PLUGIN_TOKEN`, `DESCRIBE_ME_PLUGIN_PROTO`),
gère la sérialisation JSON sur `stdout` et relaie les erreurs sur `stderr` avec le
code de sortie fourni (`PluginErrorReport::with_exit_code`). L’API historique
`Plugin` + `describe_me_plugin_main!` reste disponible pour compatibilité.

## 3. Construire et tester localement

```bash
cargo build --release -p describe-me-plugin-inventory
# Exécution via la CLI (injecte le handshake et le timeout)
describe-me plugin run --name inventory --arg --probe --arg /etc/ssl/certs
```

Les binaires doivent s’appeler `describe-me-plugin-<nom>` et n’acceptent que des arguments sérialisables sur stdout en JSON.

## 4. Installer le binaire

1. Copier l’exécutable dans `/usr/lib/describe_me/plugins/describe-me-plugin-<nom>`.
2. Vérifier les permissions (`0755`) et la présence du bit exécutable.
3. Calculer l’empreinte SHA-256 (ex. `sha256sum /usr/lib/describe_me/plugins/...`).

`describe_me` refuse tout binaire hors de ce répertoire et vérifie l’empreinte avant chaque lancement.

## 5. Déclarer le plugin dans la configuration

```toml
[extensions]
[[extensions.plugins]]
name = "inventory"
path = "/usr/lib/describe_me/plugins/describe-me-plugin-inventory"
sha256 = "7f51e8..."
args = ["--probe", "/etc/ssl/certs"]
timeout_secs = 15
```

- `path` doit être absolu et pointer vers le binaire whiteliste.
- `sha256` est obligatoire (64 hexa). Toute divergence bloque l’exécution et journalise `LogEvent::PluginError`.
- `args` et `timeout_secs` sont optionnels (10 s par défaut, minimum 1 s).

## 6. Distribution (paquet/systemd)

Lorsqu’un paquet Debian ou une image installe un plugin :

1. Ajouter le binaire dans `usr/lib/describe_me/plugins/`.
2. Fournir la configuration `extensions.plugins` correspondante (voir `packaging/config/config.toml`).
3. Documenter comment régénérer le hash après reconstruction.

## 7. Diagnostic

- `describe-me plugin run --name <nom>` permet de tester manuellement un plugin installé.
- Les erreurs (hash incorrect, permissions, timeout, JSON invalide, handshake manquant) sont visibles dans les logs (`LogEvent::PluginError`) et dans la sortie CLI.
- En cas de rejet, `describe_me` applique un jitter (100–500 ms) pour ralentir les tentatives répétées.

En suivant ces étapes, tout nouveau module reste aligné sur la politique de sécurité : poignée de main stricte, binaire whiteliste, hash immuable et configuration explicite.

## 8. Protocole minimal (interop Python/Go)

- Le lanceur fournit quatre variables d’environnement :  
  `DESCRIBE_ME_HOST=describe_me`, `DESCRIBE_ME_PLUGIN_NAME=<nom>`,
  `DESCRIBE_ME_PLUGIN_PROTO=v1`, `DESCRIBE_ME_PLUGIN_TOKEN=<hex>`. Vérifiez-les
  avant d’émettre la moindre sortie.
- Le plugin écrit un objet JSON sur `stdout` (clé/valeur). Exemple minimal :
  `{"version":1,"status":"ok"}`. Les clés et types sont libres mais doivent
  rester sérialisables par `serde_json`.
- Les erreurs doivent aller sur `stderr` et retourner un code ≠ 0. Vous pouvez
  définir vos propres codes de sortie pour distinguer les échecs « soft » (ex :
  pas de runtime conteneur) des erreurs critiques.

Pseudo-code (Python) :

```python
import json, os, sys

host = os.environ.get("DESCRIBE_ME_HOST")
name = os.environ.get("DESCRIBE_ME_PLUGIN_NAME")
proto = os.environ.get("DESCRIBE_ME_PLUGIN_PROTO")
token = os.environ.get("DESCRIBE_ME_PLUGIN_TOKEN")
if host != "describe_me" or proto != "v1" or not token or name != "inventory":
    print("handshake describe_me invalide", file=sys.stderr)
    sys.exit(1)

payload = {"version": 1, "status": "ok"}
json.dump(payload, sys.stdout)
sys.stdout.flush()
sys.exit(0)
```

## 9. Confinement et règles de chemin

- Par défaut, seuls les binaires situés sous `/usr/lib/describe_me/plugins/` sont autorisés. Les chemins sont **canonicalisés** (résolution symlinks) et les composants `..` sont refusés ; une cible finale hors du root (ex. symlink qui pointe ailleurs) est rejetée.
- Les permissions Unix sont vérifiées : binaire régulier, bit exécutable requis (sauf override), et refus si group/world-writable.
- Le hash SHA-256 est recalculé juste avant l’exécution et l’identité du fichier (inode/mtime/size) est recontrôlée pour éviter un swap entre la vérification et le spawn.
- Les exécutions ad-hoc (`describe-me plugin run --name … --path …`) appliquent les mêmes règles et n’acceptent qu’un chemin absolu sous le root configuré (customisable via `PluginPolicy::with_root` côté SDK interne).
