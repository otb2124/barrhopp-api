package com.barrhopp.api.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Placeholder security config, per proposal §4.2: "worth having basic auth/JWT
 * scaffolding in place for the user-submission endpoints."
 *
 * Currently permits all requests — there is no JWT filter or user store wired up
 * yet. This only establishes: stateless sessions (no HTTP session / JSESSIONID,
 * since auth will be token-based), and CSRF disabled (irrelevant for a
 * token-authenticated REST API with no cookie-based session).
 *
 * When user-submission auth is actually built (proposal step 5), this is where
 * a JWT decoder/filter and endpoint-level authorization rules (e.g. rate-limiting
 * POST /venues/{id}/facts) get added.
 */
@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll());

        return http.build();
    }

}
