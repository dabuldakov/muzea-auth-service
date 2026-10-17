package com.muzea.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Настройки приложения: CORS и отправка писем.
 */
@ConfigurationProperties(prefix = "app")
public record AppProperties(Cors cors, Mail mail) {

    public record Cors(List<String> allowedOrigins) {
    }

    public record Mail(boolean enabled, String from) {
    }
}
