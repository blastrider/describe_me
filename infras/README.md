# Environnement Vagrant multi‑distros pour describe_me

Ce répertoire fournit un `Vagrantfile` pour démarrer rapidement plusieurs VM Linux (Debian, Ubuntu, Fedora, Alma, Rocky) ainsi qu'une VM FreeBSD 14.3. Les VMs Linux déploient `describe-me` en service systemd avec HTTPS; la VM FreeBSD copie le binaire précompilé depuis `artifacts/freebsd`, génère une config TLS minimale et installe un service rc.d.

## Prérequis

- VirtualBox 7.x
- Vagrant 2.3+
- (Optionnel) Plugin `vagrant-vbguest` pour aligner les Guest Additions

## Réseaux et ports

- IP privée (host‑only): `192.168.56.50 + index` (Debian=50, Ubuntu=51, Fedora=52, Alma=53, Rocky=54, FreeBSD=55)
- NAT 8443 → hôte: `18443 + index`
  - Debian: 18443, Ubuntu: 18444, Fedora: 18445, Alma: 18446, Rocky: 18447, FreeBSD: 18448
- Sur les VMs Linux, le service écoute sur `0.0.0.0:8443`; FreeBSD fournit un service rc.d (`describe_me`) prêt à activer.

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
  - Pour Debian/Ubuntu: `cargo deb` génère un paquet sous `target/debian/describe-me_<version>_amd64.deb`; les VMs tenteront de l’installer automatiquement (plus rapide que la recompilation).

- Option B — Laisser la VM compiler (fallback):
  - `BUILD_IN_GUEST=1 vagrant up` (ou `vagrant provision <vm>`)
  - Le provisioner installe rustup/cargo et build dans `/opt/target` (évite les soucis d’exécution dans le dossier partagé).

- Option FreeBSD — Build dans la VM (par défaut):
  - `vagrant up freebsd` installe Rust + dépendances de build (cmake, pkgconf, perl5, gmake, llvm17/libclang) via `pkg`, exporte automatiquement `LIBCLANG_PATH` et `BINDGEN_EXTRA_CLANG_ARGS`, compile `describe-me` dans `/opt/target` (target `x86_64-unknown-freebsd`, `--all-features`), copie le binaire vers `/usr/local/bin/describe-me`, génère un `config.toml` minimal et installe le service rc.d `describe_me`.
  - Fallback binaire: cherche d'abord `/opt/target/x86_64-unknown-freebsd/release/describe-me`, puis `/opt/target/release/describe-me` si le premier chemin n'existe pas.
  - Le rc.d crée `/var/run/describe_me` pour le pidfile (`/var/run/describe_me/describe_me.pid`) et `/var/db/describe_me` pour l'état, propriétaires `describe_me`.
  - Si tu veux éviter la compilation (non recommandé), tu peux toujours déposer un binaire FreeBSD dans `artifacts/freebsd/describe-me` ou `target/x86_64-unknown-freebsd/release/describe-me` avant provision, mais le provisioner reconstruit déjà dans la VM.

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
- `make vagrant-up-debian` — lance `vagrant up debian` depuis ce répertoire

## Images utilisées (publiques, overridables)

- Debian: `debian/bookworm64`
- Ubuntu: `alvistack/ubuntu-24.04`
- Fedora: `onlyoffice/base-fedora42`
- Alma: `generic/almalinux9`
- Rocky: `generic/rocky9`
- FreeBSD: Box locale `FreeBSD-14.3-RELEASE-amd64` (ajoute-la avec `vagrant box add --name FreeBSD-14.3-RELEASE-amd64 <chemin>.box`)

Override possible via variables d’environnement avant `vagrant up`:

- `BOX_DEBIAN`, `BOX_UBUNTU`, `BOX_FEDORA`, `BOX_ALMA`, `BOX_ROCKY`, `BOX_FREEBSD`, `BOX_FREEBSD_VERSION`

Exemples:

- `BOX_UBUNTU=ubuntu/noble64 vagrant up ubuntu`
- `BOX_ALMA=bento/almalinux-9 vagrant up alma`
- `BOX_FREEBSD=FreeBSD-14.3-RELEASE-amd64 vagrant up freebsd`

> FreeBSD: le provisioner attend un binaire précompilé dans `artifacts/freebsd/describe-me`, copie `/usr/local/bin/describe-me`, génère `/usr/local/etc/describe_me/config.toml` + certs auto-signés, et installe le service rc.d `describe_me`. Active-le si besoin avec `sysrc describe_me_enable=YES && service describe_me start`.

## Variables utiles

- `WEB_TOKEN_HASH`: Hash Argon2/bcrypt à écrire tel quel dans le TOML (recommandé).
- `WEB_TOKEN`: Secret en clair à hasher pendant le provisionnement (si `WEB_TOKEN_HASH` non fourni).
- `BUILD_IN_GUEST=1`: Autorise la compilation du binaire dans la VM si aucun binaire portable n’est détecté.
- `BINARY`: Nom du binaire (défaut: `describe-me`).
- `BINARY_REL_PATH`: Chemin relatif sous `target/` si tu ranges ailleurs le binaire.
- `SYNC_HOST_DIR`: Répertoire `target` à monter (défaut: `../target`). Le provisioner s’en passe si absent.
- `SYNC_WORKSPACE_DIR`: Racine du repo à monter (défaut: `..`), utilisée pour compiler dans la VM et copier des certs.
- `BUILD_DEB_IN_GUEST`: `1` pour forcer la recompilation du paquet `.deb` dans la VM si celui fourni n’est pas compatible (glibc trop récente), `0` pour désactiver ce fallback (défaut: `auto`).

Astuce : si ta machine hôte tourne sur Ubuntu ou Mint avec une glibc plus récente que Debian 12, construis un paquet `.deb` compatible dans un conteneur `debian:12` en appelant depuis la racine du repo :

```bash
make deb-bookworm
```

Le fichier généré dans `target/debian/` sera ensuite accepté par les VM Bookworm sans dépendance manquante.

## Déploiement dans la VM

- Linux (Debian/Ubuntu/Fedora/Alma/Rocky):
  - Binaire: `/opt/describe_me/describe-me`
  - Config TOML: `/etc/describe_me/config.toml`
  - Certs: `/etc/describe_me/certs/server.pem` et `server-key.pem`
  - Service systemd: `describe_me.service`
  - Répertoire d’état (DB): `/var/lib/describe_me` (propriétaire `describe_me`)

- FreeBSD:
  - Binaire: `/usr/local/bin/describe-me` (copié depuis `artifacts/freebsd/describe-me`)
  - Config TOML: `/usr/local/etc/describe_me/config.toml` (générée si absente)
  - Certs: `/usr/local/etc/describe_me/certs/server.pem` et `server-key.pem` (auto-signés)
  - Service rc.d: `describe_me` (`sysrc describe_me_enable=YES` puis `service describe_me restart`)
  - Répertoire d’état: `/var/db/describe_me` (propriétaire `describe_me`)

La configuration Linux est calquée sur `src/examples/config_tls.toml` (HTTPS, `web.exposure`, `web.security`, etc.). La configuration FreeBSD est minimaliste (HTTPS, allowlist privée, token bcrypt). Le `token` est toujours écrit entre guillemets.

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
