## Web (Axum) rules

- Keep handlers thin; service layer does the logic; HTTP layer maps to sanitized errors.
- Origin / proxy trust:
  - Never trust `Forwarded` / `X-Forwarded-Proto` unless caller IP matches trusted proxies.
  - Default scheme comes from runtime config (http vs https).
- Security stack already exists (OriginCheckLayer + CSP/security headers + WebSecurity):
  - preserve it; add routes through the same layers.
- Sessions:
  - cookie session TTL must stay aligned with server-side TTL.
- Rate-limits / brute-force:
  - follow existing policy objects and limits (don’t invent a parallel system).
