package com.muzea.auth.security;

import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RedisRateLimitStoreTest {

    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);

    @Test
    void disabledStoreReturnsNullForFallback() {
        RedisRateLimitStore store = new RedisRateLimitStore(redis, false);

        assertThat(store.checkAndRecord("c", "cd", 10, 1)).isNull();
    }

    @Test
    void mapsAllowedCooldownAndLimit() {
        RedisRateLimitStore store = new RedisRateLimitStore(redis, true);
        when(redis.execute(any(), anyList(), any(Object[].class)))
                .thenReturn(1L, 0L, -1L);

        assertThat(store.checkAndRecord("c", "cd", 10, 1))
                .isEqualTo(RedisRateLimitStore.Decision.ALLOWED);
        assertThat(store.checkAndRecord("c", "cd", 10, 1))
                .isEqualTo(RedisRateLimitStore.Decision.COOLDOWN);
        assertThat(store.checkAndRecord("c", "cd", 10, 1))
                .isEqualTo(RedisRateLimitStore.Decision.LIMIT);
    }

    @Test
    void redisFailureReturnsNullForFallback() {
        RedisRateLimitStore store = new RedisRateLimitStore(redis, true);
        when(redis.execute(any(), anyList(), any(Object[].class)))
                .thenThrow(new IllegalStateException("redis down"));

        assertThat(store.checkAndRecord("c", "cd", 10, 1)).isNull();
    }
}
