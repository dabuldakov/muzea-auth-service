package com.muzea.auth.security;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.muzea.auth.config.AuthProperties;
import com.muzea.auth.error.AuthException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Грубый лимит запросов на IP для публичных auth-эндпоинтов (register/otp и
 * т.п.): защита от перебора и спама с одного адреса. В prod счётчики общие
 * (Redis, {@link RedisRateLimitStore}); если Redis недоступен — локальный
 * Caffeine-fallback.
 */
@Component
@RequiredArgsConstructor
public class IpRateLimiter {

    private final AuthProperties properties;

    /** Может отсутствовать в unit-тестах; при null работает локальный fallback. */
    @Autowired(required = false)
    private RedisRateLimitStore redisStore;

    private final Cache<String, Deque<Instant>> hits =
            Caffeine.newBuilder().expireAfterWrite(Duration.ofHours(1)).build();

    public void checkAndRecord(String ip) {
        if (ip == null || ip.isBlank()) {
            return;
        }

        if (redisStore != null) {
            RedisRateLimitStore.Decision decision = redisStore.checkAndRecord(
                    "auth:rl:ip:" + ip + ":hour",
                    "auth:rl:ip:" + ip + ":cooldown",
                    properties.rateLimit().perIpHourly(),
                    properties.rateLimit().ipCooldownSeconds());
            if (decision == RedisRateLimitStore.Decision.COOLDOWN) {
                throw AuthException.tooManyRequests("ip_cooldown", "Too many requests, slow down");
            }
            if (decision == RedisRateLimitStore.Decision.LIMIT) {
                throw AuthException.tooManyRequests("ip_rate_limit", "Too many requests from this IP");
            }
            if (decision == RedisRateLimitStore.Decision.ALLOWED) {
                return;
            }
        }

        Instant now = Instant.now();
        Deque<Instant> history = hits.get(ip, k -> new ArrayDeque<>());
        synchronized (history) {
            Instant cutoff = now.minus(1, ChronoUnit.HOURS);
            while (!history.isEmpty() && history.peekFirst().isBefore(cutoff)) {
                history.pollFirst();
            }
            if (!history.isEmpty()) {
                long cooldown = properties.rateLimit().ipCooldownSeconds();
                if (cooldown > 0 && history.peekLast().plusSeconds(cooldown).isAfter(now)) {
                    throw AuthException.tooManyRequests("ip_cooldown", "Too many requests, slow down");
                }
            }
            if (history.size() >= properties.rateLimit().perIpHourly()) {
                throw AuthException.tooManyRequests("ip_rate_limit", "Too many requests from this IP");
            }
            history.addLast(now);
        }
    }
}
