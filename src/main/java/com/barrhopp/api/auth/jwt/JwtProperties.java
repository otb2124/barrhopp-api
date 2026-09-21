package com.barrhopp.api.auth.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Bound from jwt.* in application.yml. secret MUST be overridden via the
 * JWT_SECRET env var outside local dev - the default in application-local.yml
 * is fine for a throwaway local Postgres instance but must never reach a real
 * deployment (see application.yml comment on this property).
 */
@ConfigurationProperties(prefix = "jwt")
public record JwtProperties(
    String secret,
    long accessTokenTtlMinutes
) {
}