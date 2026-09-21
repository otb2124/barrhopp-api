package com.barrhopp.api.auth.dto;

import com.barrhopp.api.user.Role;
import com.barrhopp.api.user.User;
import java.time.Instant;
import java.util.UUID;

/** Public view of a user. Never expose the entity directly: it carries passwordHash. */
public record UserResponse(
    UUID id,
    String email,
    String displayName,
    Role role,
    Instant createdAt
) {
    public static UserResponse from(User user) {
        return new UserResponse(
            user.getId(), user.getEmail(), user.getDisplayName(),
            user.getRole(), user.getCreatedAt());
    }
}
