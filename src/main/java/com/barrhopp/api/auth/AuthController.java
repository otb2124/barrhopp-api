package com.barrhopp.api.auth;

import com.barrhopp.api.auth.dto.AuthResponse;
import com.barrhopp.api.auth.dto.LoginRequest;
import com.barrhopp.api.auth.dto.RegisterRequest;
import com.barrhopp.api.auth.dto.UserResponse;
import com.barrhopp.api.auth.jwt.JwtProperties;
import com.barrhopp.api.user.User;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
public class AuthController {

    private final AuthService authService;
    private final JwtProperties jwtProperties;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@Valid @RequestBody RegisterRequest request) {
        AuthResponse response = authService.register(request);
        return withAuthCookie(response, HttpStatus.CREATED);
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest request) {
        AuthResponse response = authService.login(request);
        return withAuthCookie(response, HttpStatus.OK);
    }

    /**
     * Clears the auth cookie. Logout is idempotent by design - calling this
     * with no cookie present (or an already-expired one) still returns 204,
     * it never fails.
     */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout() {
        ResponseCookie cleared = ResponseCookie.from(jwtProperties.cookieName(), "")
            .httpOnly(true)
            .secure(jwtProperties.cookieSecure())
            .sameSite(jwtProperties.cookieSameSite())
            .path("/")
            .maxAge(0)
            .build();
        return ResponseEntity.noContent()
            .header(HttpHeaders.SET_COOKIE, cleared.toString())
            .build();
    }

    /** Returns the caller identified by the auth cookie (or bearer token). Handy for client bootstrapping. */
    @GetMapping("/me")
    public UserResponse me(@AuthenticationPrincipal User user) {
        return UserResponse.from(user);
    }

    /**
     * Ships the access token as an HttpOnly cookie so the browser persists
     * the session across refreshes without JS ever touching the token
     * directly. The token is still echoed in the response body for
     * non-browser clients (mobile apps, scripts) - the Angular SPA should
     * ignore that field and rely on the cookie instead.
     */
    private ResponseEntity<AuthResponse> withAuthCookie(AuthResponse response, HttpStatus status) {
        ResponseCookie cookie = ResponseCookie.from(jwtProperties.cookieName(), response.accessToken())
            .httpOnly(true)
            .secure(jwtProperties.cookieSecure())
            .sameSite(jwtProperties.cookieSameSite())
            .path("/")
            .maxAge(response.expiresInSeconds())
            .build();
        return ResponseEntity.status(status)
            .header(HttpHeaders.SET_COOKIE, cookie.toString())
            .body(response);
    }
}