package com.barrhopp.api.auth;

import com.barrhopp.api.auth.dto.AuthResponse;
import com.barrhopp.api.auth.dto.LoginRequest;
import com.barrhopp.api.auth.dto.RegisterRequest;
import com.barrhopp.api.auth.dto.UserResponse;
import com.barrhopp.api.auth.jwt.JwtProperties;
import com.barrhopp.api.auth.jwt.JwtTokenProvider;
import com.barrhopp.api.common.EmailAlreadyExistsException;
import com.barrhopp.api.user.User;
import com.barrhopp.api.user.UserRepository;
import java.util.Locale;
import lombok.RequiredArgsConstructor;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider tokenProvider;
    private final JwtProperties jwtProperties;

    @Transactional
    public AuthResponse register(RegisterRequest request) {
        String email = normalize(request.email());

        if (userRepository.existsByEmail(email)) {
            throw new EmailAlreadyExistsException(email);
        }

        User user = User.newUser(email, passwordEncoder.encode(request.password()), request.displayName().trim());
        try {
            // saveAndFlush so a unique-constraint race surfaces here, not at commit.
            user = userRepository.saveAndFlush(user);
        } catch (DataIntegrityViolationException e) {
            // Two concurrent registrations passed existsByEmail; the DB constraint wins.
            throw new EmailAlreadyExistsException(email);
        }

        return toResponse(user);
    }

    public AuthResponse login(LoginRequest request) {
        // Throws AuthenticationException (-> 401) on bad credentials.
        Authentication auth = authenticationManager.authenticate(
            new UsernamePasswordAuthenticationToken(normalize(request.email()), request.password()));

        return toResponse((User) auth.getPrincipal());
    }

    private AuthResponse toResponse(User user) {
        String token = tokenProvider.issueAccessToken(user.getEmail());
        return AuthResponse.bearer(token, jwtProperties.accessTokenTtlMinutes() * 60, UserResponse.from(user));
    }

    /** Emails are case-insensitive in practice; store and look up one canonical form. */
    private static String normalize(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }
}
