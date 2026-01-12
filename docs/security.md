# Securite operateur

Ce document consolide les points de securite deja documentes pour le mode web.

## Jetons d'acces (web)

- Le token configure dans `web.token` doit etre un hash Argon2id ou bcrypt.
- Ne jamais stocker le secret en clair dans le fichier de config.
- Helpers CLI : `describe-me --hash-web-token` et `--hash-web-token-stdin`.
- L'auth accepte `Authorization: Bearer <token>` ou `x-describe-me-token`.

References : `docs/web-security.md`, `docs/web-auth.md`,
`docs/config.reference.toml`.

## Rotation de token

- Generer un nouveau hash via `describe-me --hash-web-token`.
- Mettre a jour `web.token` et redeployer la configuration.
- Invalidation immediate des sessions : a completer (depend du runtime).

Reference : `docs/web-auth.md`.

## TLS et cookies de session

- Le cookie `describe_me_session` est `HttpOnly` et `Secure`.
- Il n'est envoye par le navigateur qu'en HTTPS.
- Mode dev HTTP uniquement : `--web-dev` ou `web.dev_insecure_session_cookie = true`.

References : `docs/web-auth.md`, `docs/web-security.md`,
`docs/config.reference.toml`.

## Proxies de confiance et origins

- `trusted_proxies` controle l'acceptation de `X-Forwarded-For`.
- `allow_origins` doit correspondre au `Host` public.
- En reverse-proxy, conserver l'en-tete `Host` d'origine.

Reference : `docs/web-security.md`.

## Rate limiting et anti-bruteforce

- Regles definies sous `[web.security]` et sous-sections
  (`html`, `sse`, `history`, `logs`, `brute_force`).
- Parametres exposes dans `docs/config.reference.toml`.

References : `docs/web-security.md`, `docs/config.reference.toml`.

## Journalisation des incidents

- Les anomalies de securite emettent `LogEvent::SecurityIncident`.
- Pour l'exploitation des logs : voir `docs/observability.md`.

Reference : `docs/web-security.md`.
