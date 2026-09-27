# Runbook: Identity provider or JWKS unavailable

> Operational runbook (no alert fires it directly). Metric names are Prometheus names of the
> catalogue in `src/asic/observability/catalogue.py`. Nothing here has been exercised in a real
> production environment; each step names the command or signal it relies on.

## Symptoms

Authenticated requests fail with 401 and reason `keys_unavailable` or `key_id_unknown` in the
authentication-failure logs; the API is otherwise healthy (`/readyz` does not depend on the IdP).

## How the verifier behaves

Public keys are fetched from `ASIC_OIDC_JWKS_URL` and cached for 300 s
(`JWKS_CACHE_TTL_SECONDS`). If the IdP is unreachable, the last known-good keys keep being used for
at most 600 s (`JWKS_MAX_STALE_SECONDS`); after that, authentication **fails closed**. An unknown
`kid` triggers a bounded refresh, so a storm of unknown keys cannot hammer the IdP.

## Diagnose

1. `curl -sf "$ASIC_OIDC_JWKS_URL"` from inside the cluster (the egress gateway must allow it).
2. Egress: the API's NetworkPolicy and the gateway allow-list for the IdP.
3. Key rotation at the IdP: a token signed with a brand-new key is accepted once the refresh sees it.
4. `lifetime_exceeded` rejections are not an outage: the IdP issues tokens longer than
   `ASIC_JWT_MAX_LIFETIME_SECONDS` (default 3600 s); shorten them at the IdP.

## Mitigate

Restore IdP reachability. Ingestion connectors and operators regain access as soon as keys refresh.

## Do not

Do not switch `ASIC_AUTH_MODE` to `development_hs256` in production (refused at startup) and do not
widen the maximum token lifetime to paper over an outage.
