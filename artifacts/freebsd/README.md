# Artéfacts FreeBSD pour Vagrant

Place ici un binaire FreeBSD prêt à l'emploi nommé `describe-me`. Il sera monté dans la VM sous `/srv/describe_me_artifacts` puis copié vers `/usr/local/bin/describe-me` pendant le provisionnement.

Exemple de build (depuis la racine du repo) pour la cible `x86_64-unknown-freebsd` :

```bash
CARGO_TARGET_DIR=artifacts/freebsd cargo build --release --target x86_64-unknown-freebsd --features "cli web config net"
cp artifacts/freebsd/x86_64-unknown-freebsd/release/describe-me artifacts/freebsd/describe-me
```

Tu peux aussi déposer ici un binaire déjà compilé ailleurs (nom exact `describe-me`). Les plugins ne sont pas obligatoires pour l'instant, mais peuvent être copiés dans ce dossier si tu veux les embarquer manuellement.
