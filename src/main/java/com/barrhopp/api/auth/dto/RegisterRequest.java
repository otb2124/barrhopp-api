package com.barrhopp.api.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterRequest(
    @NotBlank @Email @Size(max = 255) String email,
    // BCrypt silently truncates input past 72 bytes, so cap the length rather
    // than let two different long passwords hash identically.
    @NotBlank @Size(min = 8, max = 72) String password,
    @NotBlank @Size(max = 100) String displayName
) {
}
