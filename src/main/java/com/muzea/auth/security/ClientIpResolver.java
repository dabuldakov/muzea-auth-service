package com.muzea.auth.security;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Определяет IP клиента для rate-limit.
 *
 * <p>{@code X-Forwarded-For} доверяем только при явно включённом
 * {@code app.trust-proxy-headers=true} (приложение за доверенным прокси,
 * который сам перезаписывает заголовок). По умолчанию берём {@code remoteAddr},
 * чтобы клиент не мог подменить IP и обойти лимит.
 */
@Component
public class ClientIpResolver {

    private final boolean trustProxyHeaders;

    public ClientIpResolver(
            @Value("${app.trust-proxy-headers:false}") boolean trustProxyHeaders) {
        this.trustProxyHeaders = trustProxyHeaders;
    }

    public String resolve(HttpServletRequest request) {
        if (trustProxyHeaders) {
            String forwarded = request.getHeader("X-Forwarded-For");
            if (forwarded != null && !forwarded.isBlank()) {
                String first = forwarded.split(",")[0].trim();
                if (!first.isEmpty()) {
                    return first;
                }
            }
        }
        return request.getRemoteAddr();
    }
}
