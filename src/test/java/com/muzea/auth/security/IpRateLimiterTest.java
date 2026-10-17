package com.muzea.auth.security;

import com.muzea.auth.config.AuthProperties;
import com.muzea.auth.error.AuthException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IpRateLimiterTest {

    private AuthProperties properties(int perHourly, long cooldown) {
        return new AuthProperties("iss", List.of("aud"), 900, 3600,
                new AuthProperties.Rsa("", "kid"),
                new AuthProperties.Otp(6, 600, 5, 60, 5),
                new AuthProperties.RateLimit(perHourly, cooldown));
    }

    @Test
    void blocksRequestsWithinCooldown() {
        IpRateLimiter limiter = new IpRateLimiter(properties(10, 60));

        limiter.checkAndRecord("1.2.3.4");

        assertThatThrownBy(() -> limiter.checkAndRecord("1.2.3.4"))
                .isInstanceOf(AuthException.class)
                .satisfies(ex -> assertThat(((AuthException) ex).status())
                        .isEqualTo(HttpStatus.TOO_MANY_REQUESTS));
    }

    @Test
    void enforcesHourlyLimit() {
        IpRateLimiter limiter = new IpRateLimiter(properties(2, 0));

        limiter.checkAndRecord("1.2.3.4");
        limiter.checkAndRecord("1.2.3.4");

        assertThatThrownBy(() -> limiter.checkAndRecord("1.2.3.4"))
                .isInstanceOf(AuthException.class);
    }

    @Test
    void ignoresBlankIp() {
        IpRateLimiter limiter = new IpRateLimiter(properties(1, 60));

        assertThatCode(() -> limiter.checkAndRecord(null)).doesNotThrowAnyException();
        assertThatCode(() -> limiter.checkAndRecord("")).doesNotThrowAnyException();
    }
}
