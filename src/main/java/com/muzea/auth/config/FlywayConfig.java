package com.muzea.auth.config;

import org.flywaydb.core.Flyway;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.sql.DataSource;

/**
 * Spring Boot 4 больше не содержит автоконфигурацию Flyway
 * (в spring-boot-autoconfigure отсутствует FlywayAutoConfiguration),
 * поэтому `spring.flyway.*` сам по себе ничего не запускает.
 * Здесь Flyway создаётся и применяется вручную: initMethod="migrate" выполняет
 * миграции при старте приложения (до обработки запросов).
 */
@Configuration
public class FlywayConfig {

    @Bean(initMethod = "migrate")
    @ConditionalOnProperty(name = "spring.flyway.enabled", havingValue = "true", matchIfMissing = true)
    public Flyway flyway(DataSource dataSource,
                         @Value("${spring.flyway.locations:classpath:db/migration}") String locations,
                         @Value("${spring.flyway.baseline-version:1}") String baselineVersion,
                         @Value("${spring.flyway.validate-on-migrate:false}") boolean validateOnMigrate,
                         @Value("${spring.flyway.table:flyway_schema_history}") String historyTable) {
        return Flyway.configure()
                .dataSource(dataSource)
                .locations(locations)
                .table(historyTable)
                .baselineOnMigrate(true)
                .baselineVersion(baselineVersion)
                .validateOnMigrate(validateOnMigrate)
                .load();
    }
}
