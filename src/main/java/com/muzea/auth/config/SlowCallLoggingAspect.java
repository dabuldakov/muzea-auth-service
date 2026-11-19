package com.muzea.auth.config;

import lombok.extern.slf4j.Slf4j;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Замер длительности методов бизнес-слоя.
 *
 * <p>Пишет WARN только для медленных вызовов и DEBUG для остальных, поэтому
 * в проде (INFO) не засоряет логи. Аргументы и результат не логируются —
 * в них могут быть персональные данные.
 */
@Slf4j
@Aspect
@Component
public class SlowCallLoggingAspect {

    @Value("${app.logging.slow-ms:500}")
    private long slowMs;

    @Around("within(@org.springframework.stereotype.Service *)")
    public Object logSlowCall(ProceedingJoinPoint joinPoint) throws Throwable {
        long started = System.nanoTime();
        String target = joinPoint.getSignature().getDeclaringType().getSimpleName()
                + "#" + joinPoint.getSignature().getName();
        try {
            Object result = joinPoint.proceed();
            logDuration(target, started, null);
            return result;
        } catch (Throwable error) {
            logDuration(target, started, error.getClass().getSimpleName());
            throw error;
        }
    }

    private void logDuration(String target, long started, String error) {
        long ms = (System.nanoTime() - started) / 1_000_000;
        if (error != null) {
            log.warn("SERVICE {} failed after {}ms ({})", target, ms, error);
        } else if (ms >= slowMs) {
            log.warn("SLOW SERVICE {} took {}ms", target, ms);
        } else {
            log.debug("SERVICE {} took {}ms", target, ms);
        }
    }
}
