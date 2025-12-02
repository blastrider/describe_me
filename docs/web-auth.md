# Web — Auth et sessions (mode UI)

## Flux serveur (Axum)
- Cookie unique `describe_me_session` (HttpOnly, SameSite=Lax, Secure si HTTPS), TTL glissant `WEB_SESSION_SECONDS` (7j par défaut ou `session_ttl_seconds` via config). Max-Age du cookie = TTL effectif.
- Ordre d’auth dans `AuthGuard` : 1) cookie de session valide, 2) `Authorization: Bearer <token>` ou `x-describe-me-token`, sinon 401 avec cookie vidé. Origin policy et rate limits restent appliqués.
- `SessionManager` réutilisable : l’ID `sess:v1:<base64>` est accepté tant qu’il n’est pas expiré; chaque requête valide étend l’expiry (plus de “one-shot”).
- `/auth/login` (POST JSON `{token}`) → vérifie hash argon2id/bcrypt → crée/rafraîchit la session → 303 `/` + Set-Cookie. `/auth/logout` efface le cookie.
- Routes protégées (`/`, `/sse`, `/api/history`, `/api/logs`, `/api/containers`, `/api/description`, `/api/tags`, `/metrics`, `/updates`, `/logs`) passent par `AuthGuard` et rafraîchissent le cookie via `attach_session_cookie`; 401 nettoie le cookie via `SecurityRejection`.
- Ajouter une nouvelle route protégée : placer `AuthGuard` en extracteur et appeler `attach_session_cookie` sur la réponse; ne jamais stocker de jeton brut côté client.

## Flux frontend (JS)
- Login modal (`token.js`) : `fetch("/auth/login", {method:"POST", headers:{"Content-Type":"application/json"}, credentials:"same-origin", body:JSON.stringify({token})})`; en succès (200/303) ferme la modale et relance SSE/API.
- SSE (`sse.js`) : `new EventSource("/sse")`; en 401 → affichage de la modale, arrêt des reconnects tant qu’on n’est pas réauthentifié; pas de manipulation du cookie côté client.
- APIs (`history-trends.js`, `logs.js`, `containers.js`, tags editor) : `credentials:"same-origin"`, sur 401 → affichent la modale et laissent `/auth/login` régénérer le cookie (pas de stockage localStorage/sessionStorage ni cookie non-HttpOnly).

## Points de vigilance
- Toujours garder Max-Age du cookie ≤ TTL serveur.
- Ne pas bypasser `AuthGuard`/`SessionManager`; conserver le fallback Bearer pour la compat CLI.
- Tester : login + SSE + `/api/history` + `/api/logs` en parallèle (même cookie), 401 sans cookie → modal, bearer toujours accepté. 
