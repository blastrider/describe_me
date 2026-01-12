# Observabilite

Ce document regroupe les points d'operation autour des logs, des metriques et
du depannage.

## Logs applicatifs

- Le binaire emet des evenements via `tracing` et `LogEvent`.
- La configuration `RUST_LOG` peut etre definie via `[runtime].rust_log`.
- Les details d'implementation sont dans `docs/logging.md`.

References : `docs/logging.md`, `docs/config.reference.toml`.

## Logs hote (journald)

- `describe-me logs --lines 200` lit les logs via `journalctl`.
- L'endpoint `GET /api/logs?lines=N` expose la meme source.
- En conteneur, monter `/run/systemd/journal/socket` et fournir `journalctl`.
- La variable `DESCRIBE_ME_JOURNALCTL` permet de pointer un binaire custom.

Reference : `docs/logs.md`.

## Metriques Prometheus

- L'endpoint `/metrics` est expose en mode web.
- La route est protegee par `AuthGuard` comme les autres endpoints web.
- L'auth accepte `Authorization: Bearer <token>` ou `x-describe-me-token`.
- Les extensions peuvent exposer des valeurs numeriques (voir `docs/plugins.md`).

References : `docs/web-auth.md`, `docs/plugins.md`.

Exemple (adapter le host/port) :

```bash
curl -H "Authorization: Bearer <token>" http://127.0.0.1:8080/metrics
```

## Troubleshooting rapide

- 401 : pas de session valide ni token valide (`docs/web-auth.md`).
- Cookie session non envoye en HTTP : utiliser HTTPS ou `--web-dev` en dev.
- Journald indisponible : verifier le socket et `DESCRIBE_ME_JOURNALCTL`.
- Plugins absents : verifier `sha256`, chemin et timeout (`docs/plugins.md`).
- Config non chargee : verifier `--config <path>` et la feature `config`.

References : `docs/web-auth.md`, `docs/logs.md`, `docs/plugins.md`, `docs/cli.md`.
