package com.muzea.auth.security;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;

/** Проверяет, что access-токен адресован одному из ожидаемых ресурс-сервисов. */
public class AudienceValidator implements OAuth2TokenValidator<Jwt> {

    private final List<String> audiences;

    public AudienceValidator(List<String> audiences) {
        this.audiences = audiences;
    }

    @Override
    public OAuth2TokenValidatorResult validate(Jwt jwt) {
        List<String> tokenAudience = jwt.getAudience();
        if (tokenAudience != null && tokenAudience.stream().anyMatch(audiences::contains)) {
            return OAuth2TokenValidatorResult.success();
        }
        OAuth2Error error = new OAuth2Error("invalid_token",
                "The required audience is missing", null);
        return OAuth2TokenValidatorResult.failure(error);
    }
}
