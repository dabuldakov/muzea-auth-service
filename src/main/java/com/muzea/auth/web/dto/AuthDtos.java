package com.muzea.auth.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.UUID;

/** Запросы и ответы API аутентификации. */
public final class AuthDtos {

    private AuthDtos() {
    }

    public record RegisterRequest(
            @NotBlank @Email @Size(max = 255) String email,
            @NotBlank @Size(min = 3, max = 64)
            @Pattern(regexp = "^[A-Za-z0-9_.]+$", message = "Only letters, digits, '_' and '.' are allowed")
            String username,
            @Size(max = 128) String displayName
    ) {
    }

    public record VerifyEmailRequest(
            @NotBlank @Email String email,
            @NotBlank String code,
            @Size(max = 128) String deviceId
    ) {
    }

    public record ResendVerificationRequest(@NotBlank @Email String email) {
    }

    public record OtpRequest(@NotBlank @Email String email) {
    }

    public record OtpVerifyRequest(
            @NotBlank @Email String email,
            @NotBlank String code,
            @Size(max = 128) String deviceId,
            @Size(max = 128) String deviceName
    ) {
    }

    public record RefreshRequest(
            @NotBlank String refreshToken,
            @Size(max = 128) String deviceId
    ) {
    }

    public record LogoutRequest(@NotBlank String refreshToken) {
    }

    public record TokenResponse(
            String accessToken,
            String refreshToken,
            String tokenType,
            long expiresIn,
            UserResponse user
    ) {
    }

    public record UserResponse(
            UUID id,
            String email,
            String username,
            String displayName,
            boolean emailVerified
    ) {
    }

    public record SessionResponse(
            UUID id,
            String deviceId,
            String userAgent,
            String ip,
            Instant createdAt,
            Instant lastUsedAt
    ) {
    }

    public record MessageResponse(String message) {
    }

    public record ApiError(String code, String message) {
    }
}
