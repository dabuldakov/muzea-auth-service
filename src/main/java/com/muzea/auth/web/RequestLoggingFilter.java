package com.muzea.auth.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

/**
 * Логирует каждый HTTP-запрос auth-service: метод, путь, статус, длительность
 * и идентификатор пользователя.
 *
 * <p>В логи намеренно не попадают email, username, User-Agent и токены:
 * для разбора инцидентов достаточно UUID пользователя и request_id.
 */
@Slf4j
@Component
@Order(Ordered.LOWEST_PRECEDENCE)
public class RequestLoggingFilter extends OncePerRequestFilter {

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return "OPTIONS".equalsIgnoreCase(request.getMethod());
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain chain
    ) throws ServletException, IOException {
        String requestId = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        String user = currentUser();

        MDC.put("request_id", requestId);
        MDC.put("user", user);

        long start = System.currentTimeMillis();
        try {
            chain.doFilter(request, response);
            log.info("HTTP {} {} -> {} ({}ms, user={}, request_id={})",
                    request.getMethod(), request.getRequestURI(), response.getStatus(),
                    System.currentTimeMillis() - start, user, requestId);
        } catch (IOException | ServletException | RuntimeException e) {
            log.error("HTTP {} {} -> ERROR after {}ms (user={}, request_id={})",
                    request.getMethod(), request.getRequestURI(),
                    System.currentTimeMillis() - start, user, requestId, e);
            throw e;
        } finally {
            MDC.remove("request_id");
            MDC.remove("user");
        }
    }

    private String currentUser() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return "-";
        }
        String name = auth.getName();
        return name == null || "anonymousUser".equals(name) ? "-" : name;
    }
}
