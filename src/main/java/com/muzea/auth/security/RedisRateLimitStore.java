package com.muzea.auth.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Общий Redis-стор для rate-limit'ов auth-service.
 *
 * <p>In-memory Caffeine на каждой ноде даёт разный лимит при нескольких
 * инстансах (60 запросов на ноду = 180 на три ноды). Здесь счётчики и
 * cooldown-ключи общие. Если Redis выключен/недоступен, метод возвращает
 * {@code null}, и вызывающий лимитер падает обратно на Caffeine.
 */
@Slf4j
@Component
public class RedisRateLimitStore {

    public enum Decision {
        ALLOWED, COOLDOWN, LIMIT
    }

    /** 1 — разрешено, 0 — cooldown, -1 — превышен лимит за час. */
    private static final DefaultRedisScript<Long> SCRIPT = new DefaultRedisScript<>("""
            if tonumber(ARGV[2]) > 0 and redis.call('EXISTS', KEYS[2]) == 1 then
              return 0
            end
            local count = tonumber(redis.call('GET', KEYS[1]) or '0')
            if count >= tonumber(ARGV[1]) then
              return -1
            end
            count = redis.call('INCR', KEYS[1])
            redis.call('EXPIRE', KEYS[1], 3600)
            if tonumber(ARGV[2]) > 0 then
              redis.call('SET', KEYS[2], '1', 'EX', ARGV[2])
            end
            return 1
            """, Long.class);

    private final StringRedisTemplate redis;
    private final boolean enabled;

    public RedisRateLimitStore(StringRedisTemplate redis,
                               @Value("${auth.rate-limit.redis-enabled:false}") boolean enabled) {
        this.redis = redis;
        this.enabled = enabled;
    }

    /**
     * @return решение или {@code null}, если Redis выключен/сломан —
     *         вызывающий должен применить локальный fallback.
     */
    public Decision checkAndRecord(String counterKey, String cooldownKey,
                                   int limitPerHour, long cooldownSeconds) {
        if (!enabled) {
            return null;
        }
        try {
            Long result = redis.execute(SCRIPT, List.of(counterKey, cooldownKey),
                    String.valueOf(limitPerHour), String.valueOf(cooldownSeconds));
            if (result == null) {
                return null;
            }
            return switch (result.intValue()) {
                case 1 -> Decision.ALLOWED;
                case 0 -> Decision.COOLDOWN;
                case -1 -> Decision.LIMIT;
                default -> null;
            };
        } catch (Exception e) {
            log.warn("Redis rate-limit unavailable, falling back to in-memory: {}", e.getMessage());
            return null;
        }
    }
}
