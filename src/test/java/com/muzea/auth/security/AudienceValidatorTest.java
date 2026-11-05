package com.muzea.auth.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AudienceValidatorTest {

    private Jwt jwt(List<String> audience) {
        Jwt.Builder builder = Jwt.withTokenValue("token").header("alg", "RS256").subject("subject");
        if (audience != null) {
            builder.audience(audience);
        }
        return builder.build();
    }

    @Test
    void acceptsMatchingAudience() {
        var result = new AudienceValidator(List.of("api-muzea", "chat-muzea"))
                .validate(jwt(List.of("chat-muzea")));

        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    void rejectsForeignAudience() {
        var result = new AudienceValidator(List.of("api-muzea"))
                .validate(jwt(List.of("other-service")));

        assertThat(result.hasErrors()).isTrue();
        assertThat(result.getErrors())
                .extracting(OAuth2Error::getErrorCode)
                .containsExactly("invalid_token");
    }

    @Test
    void rejectsMissingAudience() {
        assertThat(new AudienceValidator(List.of("api-muzea")).validate(jwt(null)).hasErrors())
                .isTrue();
    }
}
