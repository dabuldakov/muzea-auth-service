package com.muzea.auth.email;

import com.muzea.auth.config.AuthProperties;
import com.muzea.auth.error.AuthException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OtpRateLimiterTest {

    private AuthProperties properties(long cooldownSeconds, int maxPerHour) {
        return new AuthProperties("iss", List.of("aud"), 900, 3600,
                new AuthProperties.Rsa("", "kid"),
                new AuthProperties.Otp(6, 600, 5, cooldownSeconds, maxPerHour));
    }

    @Test
    void blocksRequestsWithinCooldown() {
        OtpRateLimiter limiter = new OtpRateLimiter(properties(60, 5));

        limiter.checkAndRecord("user@example.com", EmailPurpose.LOGIN);

        assertThatThrownBy(() -> limiter.checkAndRecord("user@example.com", EmailPurpose.LOGIN))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).status()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS));
    }

    @Test
    void enforcesHourlyLimitAcrossPurposesIndependently() {
        OtpRateLimiter limiter = new OtpRateLimiter(properties(0, 2));

        limiter.checkAndRecord("user@example.com", EmailPurpose.LOGIN);
        limiter.checkAndRecord("user@example.com", EmailPurpose.LOGIN);

        assertThatThrownBy(() -> limiter.checkAndRecord("user@example.com", EmailPurpose.LOGIN))
                .isInstanceOf(AuthException.class);

        // Другой email не затронут.
        limiter.checkAndRecord("other@example.com", EmailPurpose.LOGIN);
    }
}
