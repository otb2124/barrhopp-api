package com.barrhopp.api.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.barrhopp.api.auth.jwt.JwtProperties;
import com.barrhopp.api.auth.jwt.JwtTokenProvider;
import org.junit.jupiter.api.Test;

/** Pure unit tests: no Spring context, no database. */
class JwtTokenProviderTest {

    private static final String SECRET = "unit-test-secret-that-is-definitely-32+chars";

    private JwtTokenProvider provider(String secret, long ttlMinutes) {
        return new JwtTokenProvider(new JwtProperties(secret, ttlMinutes));
    }

    @Test
    void roundTripReturnsSubject() {
        JwtTokenProvider p = provider(SECRET, 15);
        String token = p.issueAccessToken("a@b.com");
        assertThat(p.validateAndGetSubject(token)).contains("a@b.com");
    }

    @Test
    void expiredTokenIsRejected() {
        // Negative TTL puts expiry in the past, so the token is born expired.
        JwtTokenProvider p = provider(SECRET, -1);
        assertThat(p.validateAndGetSubject(p.issueAccessToken("a@b.com"))).isEmpty();
    }

    @Test
    void tokenSignedWithDifferentSecretIsRejected() {
        String forged = provider("a-completely-different-secret-32-chars-min", 15).issueAccessToken("a@b.com");
        assertThat(provider(SECRET, 15).validateAndGetSubject(forged)).isEmpty();
    }

    @Test
    void tamperedPayloadIsRejected() {
        JwtTokenProvider p = provider(SECRET, 15);
        String[] parts = p.issueAccessToken("a@b.com").split("\\.");
        String tampered = parts[0] + "." + parts[1] + "x." + parts[2];
        assertThat(p.validateAndGetSubject(tampered)).isEmpty();
    }

    @Test
    void garbageAndBlankInputAreRejectedNotThrown() {
        JwtTokenProvider p = provider(SECRET, 15);
        assertThat(p.validateAndGetSubject("garbage")).isEmpty();
        assertThat(p.validateAndGetSubject("")).isEmpty();
    }

    @Test
    void shortOrMissingSecretFailsFastAtStartup() {
        assertThatThrownBy(() -> provider("too-short", 15)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> provider("", 15)).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(() -> provider(null, 15)).isInstanceOf(IllegalStateException.class);
    }
}
