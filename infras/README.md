# Environnement Vagrant multi‑distros pour describe_me

Ce répertoire fournit un `Vagrantfile` pour démarrer rapidement plusieurs VM Linux (Debian, Ubuntu, Fedora, Alma, Rocky, Arch) et y déployer `describe-me` en service systemd avec HTTPS.

## Prérequis

- VirtualBox 7.x
- Vagrant 2.3+
- (Optionnel) Plugin `vagrant-vbguest` pour aligner les Guest Additions

## Réseaux et ports

- IP privée (host‑only): `192.168.56.50 + index` (Debian=50, Ubuntu=51, Fedora=52, Alma=53, Rocky=54, Arch=55)
- NAT 8443 → hôte: `18443 + index`
  - Debian: 18443, Ubuntu: 18444, Fedora: 18445, Alma: 18446, Rocky: 18447, Arch: 18448
- Le service écoute sur `0.0.0.0:8443` dans chaque VM.

Accès depuis l’hôte:

- https://127.0.0.1:18443 (Debian)
- https://127.0.0.1:18444 (Ubuntu)
- etc.

Note: le certificat auto‑signé est émis pour l’IP de la VM (192.168.56.x). Sur 127.0.0.1, le navigateur affichera un avertissement (SAN non présent).

## Démarrage rapide

Dans tous les cas, place‑toi ici: `infras/`

1) Choisir comment fournir le binaire `describe-me`:

- Option A — Build MUSL (recommandé, portable):
  - `rustup target add x86_64-unknown-linux-musl`
  - (Debian/Ubuntu) `sudo apt-get install -y musl-tools`
  - `cargo build --release --target x86_64-unknown-linux-musl --features "cli web config systemd net"`
  - Le provisioner prendra en priorité `target/x86_64-unknown-linux-musl/release/describe-me`.

- Option B — Laisser la VM compiler (fallback):
  - `BUILD_IN_GUEST=1 vagrant up` (ou `vagrant provision <vm>`)
  - Le provisioner installe rustup/cargo et build dans `/opt/target` (évite les soucis d’exécution dans le dossier partagé).

2) Certificats TLS

- Si `openssl` est disponible dans la VM, des certs auto‑signés sont générés.
- Sinon, place des certs côté hôte dans `certs/server.pem` et `certs/server-key.pem` à la racine du repo; ils seront copiés dans la VM.

3) Jeton d’accès (obligatoire)

- Tu peux fournir un hash prêt à l’emploi pour toutes les VMs:
  - `export WEB_TOKEN_HASH='$argon2id$v=19$m=131072,t=4,p=1$Ct/TeeomYIeJaQCcYIO25Q$51bMC0RJ/C7YTqyluYsB+dNr9l/bmgokpJJ546LwhGQ'`
  - Puis `vagrant up` (ou `vagrant provision <vm>`)
- Sinon, fournis un secret à hasher:
  - `WEB_TOKEN="monsecret" vagrant provision <vm>`

4) Lancer

- Tout lancer: `vagrant up`
- Une VM: `vagrant up ubuntu`
- Reprovisionner: `vagrant provision ubuntu`
- Redémarrer + reprovisionner: `vagrant reload ubuntu --provision`

Astuce: quelques cibles Make sont disponibles ici et redirigent vers la racine du repo:

- `make fmt` — formatage (`cargo fmt`)
- `make ci` — fmt-check, clippy, tests, doc, audit, deny, bench
- `make release-complete` — build release toutes features

## Images utilisées (publiques, overridables)

- Debian: `debian/bookworm64`
- Ubuntu: `alvistack/ubuntu-24.04`
- Fedora: `onlyoffice/base-fedora42`
- Alma: `generic/almalinux9`
- Rocky: `generic/rocky9`
- Arch: `justunsix/archlinux-nix-aur`

Override possible via variables d’environnement avant `vagrant up`:

- `BOX_DEBIAN`, `BOX_UBUNTU`, `BOX_FEDORA`, `BOX_ALMA`, `BOX_ROCKY`, `BOX_ARCH`

Exemples:

- `BOX_UBUNTU=ubuntu/noble64 vagrant up ubuntu`
- `BOX_ALMA=bento/almalinux-9 vagrant up alma`

## Variables utiles

- `WEB_TOKEN_HASH`: Hash Argon2/bcrypt à écrire tel quel dans le TOML (recommandé).
- `WEB_TOKEN`: Secret en clair à hasher pendant le provisionnement (si `WEB_TOKEN_HASH` non fourni).
- `BUILD_IN_GUEST=1`: Autorise la compilation du binaire dans la VM si aucun binaire portable n’est détecté.
- `BINARY`: Nom du binaire (défaut: `describe-me`).
- `BINARY_REL_PATH`: Chemin relatif sous `target/` si tu ranges ailleurs le binaire.
- `SYNC_HOST_DIR`: Répertoire `target` à monter (défaut: `../target`). Le provisioner s’en passe si absent.
- `SYNC_WORKSPACE_DIR`: Racine du repo à monter (défaut: `..`), utilisée pour compiler dans la VM et copier des certs.

## Déploiement dans la VM

- Binaire: `/opt/describe_me/describe-me`
- Config TOML: `/etc/describe_me/config.toml`
- Certs: `/etc/describe_me/certs/server.pem` et `server-key.pem`
- Service systemd: `describe_me.service`
- Répertoire d’état (DB): `/var/lib/describe_me` (propriétaire `describe_me`)

La configuration générée est calquée sur `src/examples/config_tls.toml` (HTTPS, `web.exposure`, `web.security`, etc.). Le `token` est toujours écrit entre guillemets.

## Accès et test

- Ouvre `https://127.0.0.1:18444` (Ubuntu, par exemple), accepte l’avertissement TLS si nécessaire, saisis le jeton.
- Alternative via réseau privé: `https://192.168.56.51:8443` (selon la VM).

## Dépannage

- GLIBC trop récente (binaire hôte ne s’exécute pas):
  - Fournis un build MUSL (Option A) ou `BUILD_IN_GUEST=1`.
- Fedora: timeouts DNF → fournis des certs côté hôte dans `certs/` pour éviter d’installer `openssl`.
- Dossiers partagés/permissions build scripts: la compilation en VM utilise `CARGO_TARGET_DIR=/opt/target` (non partagé).
- Ports occupés: Vagrant applique `auto_correct`; vérifie les ports finaux avec `vagrant port <vm>`.

## Opérations courantes

- Arrêt: `vagrant halt` (ou `vagrant halt <vm>`)
- Destruction: `vagrant destroy -f` (ou par VM)
