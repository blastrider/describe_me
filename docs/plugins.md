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

```rust
use describe_me_plugin_sdk::{describe_me_plugin_main, Plugin, PluginError, PluginOutput};

#[derive(Default)]
struct Inventory;

impl Plugin for Inventory {
    fn name(&self) -> &'static str {
        "inventory"
    }

    fn collect(&self) -> Result<PluginOutput, PluginError> {
        let mut out = PluginOutput::new();
        out.insert("status", "ok");
        Ok(out)
    }
}

describe_me_plugin_main!(Inventory);
```

Le SDK charge automatiquement le *LaunchContext* (`DESCRIBE_ME_HOST`, `DESCRIBE_ME_PLUGIN_NAME`, `DESCRIBE_ME_PLUGIN_TOKEN`, `DESCRIBE_ME_PLUGIN_PROTO`) ; toute incohérence (plugin lancé hors `describe_me`, nom différent, proto ≠ `v1`, token vide) provoque un arrêt immédiat.

## 2. Construire et tester localement

```bash
cargo build --release -p describe-me-plugin-inventory
# Exécution via la CLI (injecte le handshake et le timeout)
describe-me plugin run --name inventory --arg --probe --arg /etc/ssl/certs
```

Les binaires doivent s’appeler `describe-me-plugin-<nom>` et n’acceptent que des arguments sérialisables sur stdout en JSON.

## 3. Installer le binaire

1. Copier l’exécutable dans `/usr/lib/describe_me/plugins/describe-me-plugin-<nom>`.
2. Vérifier les permissions (`0755`) et la présence du bit exécutable.
3. Calculer l’empreinte SHA-256 (ex. `sha256sum /usr/lib/describe_me/plugins/...`).

`describe_me` refuse tout binaire hors de ce répertoire et vérifie l’empreinte avant chaque lancement.

## 4. Déclarer le plugin dans la configuration

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

## 5. Distribution (paquet/systemd)

Lorsqu’un paquet Debian ou une image installe un plugin :

1. Ajouter le binaire dans `usr/lib/describe_me/plugins/`.
2. Fournir la configuration `extensions.plugins` correspondante (voir `packaging/config/config.toml`).
3. Documenter comment régénérer le hash après reconstruction.

## 6. Diagnostic

- `describe-me plugin run --name <nom>` permet de tester manuellement un plugin installé.
- Les erreurs (hash incorrect, permissions, timeout, JSON invalide, handshake manquant) sont visibles dans les logs (`LogEvent::PluginError`) et dans la sortie CLI.
- En cas de rejet, `describe_me` applique un jitter (100–500 ms) pour ralentir les tentatives répétées.

En suivant ces étapes, tout nouveau module reste aligné sur la politique de sécurité : poignée de main stricte, binaire whiteliste, hash immuable et configuration explicite.
