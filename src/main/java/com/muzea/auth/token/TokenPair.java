package com.muzea.auth.token;

/** Результат выдачи пары токенов. */
public record TokenPair(String accessToken, String refreshToken, long accessExpiresInSeconds) {
}
