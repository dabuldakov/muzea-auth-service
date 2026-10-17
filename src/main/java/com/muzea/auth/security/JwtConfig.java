package com.muzea.auth.security;

import com.muzea.auth.config.AuthProperties;
import com.muzea.auth.crypto.RsaKeyService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * Валидация собственных access-токенов (для эндпоинтов /auth/me, /auth/sessions).
 * Ресурс-сервисы настраивают такой же JwtDecoder, но с JWK Set URI.
 */
@Configuration
public class JwtConfig {

    @Bean
    public JwtDecoder jwtDecoder(RsaKeyService rsaKeyService, AuthProperties properties) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withPublicKey(rsaKeyService.publicKey())
                .build();
        OAuth2TokenValidator<Jwt> validator = new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(properties.issuer()),
                new AudienceValidator(properties.audience())
        );
        decoder.setJwtValidator(validator);
        return decoder;
    }
}
