package com.barrhopp.api.auth.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Resolves the caller's identity from either the auth cookie (what the SPA
 * relies on) or an "Authorization: Bearer <jwt>" header (kept for
 * non-browser clients). Cookie is checked first since it's the primary path.
 * An invalid/missing token is NOT rejected here - the filter just leaves the
 * request unauthenticated and lets the authorization rules in SecurityConfig
 * decide (401 for protected routes, pass-through for public).
 */
@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtTokenProvider tokenProvider;
    private final JwtProperties jwtProperties;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            resolveToken(request).ifPresent(token ->
                tokenProvider.validateAndGetSubject(token).ifPresent(email -> {
                    try {
                        // Reload from DB so a deleted user or changed role takes
                        // effect immediately instead of living on inside the token.
                        UserDetails user = userDetailsService.loadUserByUsername(email);
                        var authentication = new UsernamePasswordAuthenticationToken(
                            user, null, user.getAuthorities());
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    } catch (UsernameNotFoundException ignored) {
                        // Valid signature but the user no longer exists: stay unauthenticated.
                    }
                }));
        }

        chain.doFilter(request, response);
    }

    /** Cookie first (the SPA's path), then the Authorization header (non-browser clients). */
    private Optional<String> resolveToken(HttpServletRequest request) {
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (jwtProperties.cookieName().equals(cookie.getName())) {
                    return Optional.of(cookie.getValue());
                }
            }
        }

        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.startsWith(BEARER_PREFIX)) {
            return Optional.of(header.substring(BEARER_PREFIX.length()).trim());
        }

        return Optional.empty();
    }
}