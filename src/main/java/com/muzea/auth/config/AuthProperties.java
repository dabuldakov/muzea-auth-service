package com.muzea.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Конфигурация аутентификации: издатель/аудитория токенов, TTL, RSA-ключ и OTP.
 */
@ConfigurationProperties(prefix = "auth")
public record AuthProperties(
        String issuer,
        List<String> audience,
        long accessTokenTtlSeconds,
        long refreshTokenTtlSeconds,
        Rsa rsa,
        Otp otp
) {

    /**
     * Приватный RSA-ключ в base64 (PKCS#8). Пусто — ключ генерируется (только dev).
     */
    public record Rsa(String privateKey, String keyId) {
    }

    public record Otp(
            int length,
            long ttlSeconds,
            int maxAttempts,
            long requestCooldownSeconds,
            int maxRequestsPerHour
    ) {
    }
}
