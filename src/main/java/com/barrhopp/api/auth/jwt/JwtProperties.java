package com.barrhopp.api.auth.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Bound from jwt.* in application.yml. secret MUST be overridden via the
 * JWT_SECRET env var outside local dev - the default in application-local.yml
 * is fine for a throwaway local Postgres instance but must never reach a real
 * deployment (see application.yml comment on this property).
 *
 * cookieName/cookieSecure/cookieSameSite control the HttpOnly cookie the
 * token is shipped in. cookieSecure MUST be true in any real deployment
 * (cookieSameSite=None requires it, and plain HTTP has no business carrying
 * an auth cookie anyway) - the false default here is for local dev over
 * http://localhost only.
 */
@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(
    String secret,
    long accessTokenTtlMinutes,
    String cookieName,
    boolean cookieSecure,
    String cookieSameSite
) {
    public JwtProperties {
        if (cookieName == null || cookieName.isBlank()) {
            cookieName = "access_token";
        }
        if (cookieSameSite == null || cookieSameSite.isBlank()) {
            cookieSameSite = "Lax";
        }
    }
}