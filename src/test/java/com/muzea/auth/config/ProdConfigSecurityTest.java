package com.muzea.auth.config;

import org.junit.jupiter.api.Test;
import org.springframework.core.io.ClassPathResource;

import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Прод-профиль не должен содержать небезопасных дефолтов и не должен
 * публиковать Swagger/OpenAPI.
 */
class ProdConfigSecurityTest {

    private String prodYaml() throws Exception {
        try (var input = new ClassPathResource("application-prod.yaml").getInputStream()) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    @Test
    void datasourceRequiresEnvironmentWithoutDefaults() throws Exception {
        String yaml = prodYaml();

        assertThat(yaml).contains("url: ${DATABASE_URL}");
        assertThat(yaml).contains("username: ${DATABASE_USERNAME}");
        assertThat(yaml).contains("password: ${DATABASE_PASSWORD}");
        assertThat(yaml).doesNotContain(":admin");
    }

    @Test
    void swaggerAndApiDocsAreDisabled() throws Exception {
        String yaml = prodYaml();

        assertThat(yaml).contains("springdoc:");
        assertThat(yaml).contains("api-docs:");
        assertThat(yaml).contains("swagger-ui:");
        assertThat(yaml).contains("enabled: false");
    }
}
