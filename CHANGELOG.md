## Unreleased

- Refus explicite d'exécuter `describe-me` en root (UID 0) côté CLI.
- Ajout d'une unité systemd durcie (`packaging/systemd/describe-me.service`) avec confinement maximal (DynamicUser, NoNewPrivileges, capabilities vidées, sandbox).
