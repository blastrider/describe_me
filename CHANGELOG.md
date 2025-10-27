## Unreleased

- Refus explicite d'exécuter `describe-me` en root (UID 0) côté CLI.
- Ajout d'une unité systemd durcie (`packaging/systemd/describe-me.service`) avec confinement maximal (DynamicUser, NoNewPrivileges, capabilities vidées, sandbox).
- Mode web : le jeton n'est plus accepté dans la query-string (`?token=`), uniquement via les en-têtes `Authorization: Bearer` ou `x-describe-me-token`, avec comparaison en temps constant et nouvelle UI de saisie.
