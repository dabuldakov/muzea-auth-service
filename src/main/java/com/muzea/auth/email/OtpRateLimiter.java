package com.muzea.auth.email;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.muzea.auth.config.AuthProperties;
import com.muzea.auth.error.AuthException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;

/**
 * Ограничение частоты запросов OTP на email: пауза между запросами и лимит
 * в час. In-memory (Caffeine) — при нескольких нодах нужен общий стор.
 */
@Component
@RequiredArgsConstructor
public class OtpRateLimiter {

    private final AuthProperties properties;
    private final Cache<String, Deque<Instant>> requests =
            Caffeine.newBuilder().expireAfterWrite(Duration.ofHours(1)).build();

    /** Проверяет лимиты и регистрирует новую попытку; иначе кидает 429. */
    public void checkAndRecord(String email, EmailPurpose purpose) {
        String key = email.toLowerCase(Locale.ROOT) + ':' + purpose.name();
        Instant now = Instant.now();
        Deque<Instant> history = requests.get(key, k -> new ArrayDeque<>());
        synchronized (history) {
            Instant cutoff = now.minus(1, ChronoUnit.HOURS);
            while (!history.isEmpty() && history.peekFirst().isBefore(cutoff)) {
                history.pollFirst();
            }
            if (!history.isEmpty()) {
                Instant last = history.peekLast();
                long cooldown = properties.otp().requestCooldownSeconds();
                if (last.plusSeconds(cooldown).isAfter(now)) {
                    throw AuthException.tooManyRequests("otp_cooldown",
                            "Please wait before requesting a new code");
                }
            }
            if (history.size() >= properties.otp().maxRequestsPerHour()) {
                throw AuthException.tooManyRequests("otp_hourly_limit",
                        "Too many code requests, try again later");
            }
            history.addLast(now);
        }
    }
}
