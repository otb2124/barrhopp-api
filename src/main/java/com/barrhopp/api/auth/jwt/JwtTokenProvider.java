package com.barrhopp.api.auth.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Owns everything about the token's internal shape (claims, signing algorithm,
 * expiry). Nothing outside this class should touch io.jsonwebtoken types directly -
 * callers get back either a signed String (issue) or a validated email (parse).
 */
@Component
public class JwtTokenProvider {

    private final Key signingKey;
    private final long accessTokenTtlMinutes;

    @Autowired
    public JwtTokenProvider(JwtProperties properties) {
        if (!StringUtils.hasText(properties.secret()) || properties.secret().length() < 32) {
            // HS256 needs a key >= 256 bits; a short/missing secret is a
            // misconfiguration that should fail fast at startup, not produce
            // silently-broken tokens at runtime.
            throw new IllegalStateException(
                "jwt.secret must be set and at least 32 characters. " +
                "Set the JWT_SECRET environment variable.");
        }
        this.signingKey = Keys.hmacShaKeyFor(properties.secret().getBytes(StandardCharsets.UTF_8));
        this.accessTokenTtlMinutes = properties.accessTokenTtlMinutes();
    }

    /** Issues a signed access token for the given user email (used as the JWT subject). */
    public String issueAccessToken(String email) {
        Instant now = Instant.now();
        Instant expiry = now.plus(accessTokenTtlMinutes, ChronoUnit.MINUTES);

        return Jwts.builder()
            .subject(email)
            .issuedAt(Date.from(now))
            .expiration(Date.from(expiry))
            .signWith(signingKey)
            .compact();
    }

    /**
     * Validates signature and expiry, returning the subject (email) on success.
     * Returns empty on any failure (expired, malformed, bad signature) rather
     * than throwing - callers (the filter) should treat "invalid token" as
     * "unauthenticated," not as a 500.
     */
    public java.util.Optional<String> validateAndGetSubject(String token) {
        try {
            String subject = Jwts.parser()
                .verifyWith((javax.crypto.SecretKey) signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject();
            return java.util.Optional.ofNullable(subject);
        } catch (JwtException | IllegalArgumentException e) {
            return java.util.Optional.empty();
        }
    }
}