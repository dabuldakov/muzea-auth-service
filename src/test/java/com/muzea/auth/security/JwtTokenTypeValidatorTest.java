package com.muzea.auth.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import static org.assertj.core.api.Assertions.assertThat;

class JwtTokenTypeValidatorTest {

    private Jwt jwt(String type) {
        Jwt.Builder builder = Jwt.withTokenValue("token").header("alg", "RS256").subject("subject");
        if (type != null) {
            builder.claim("type", type);
        }
        return builder.build();
    }

    @Test
    void acceptsAccessToken() {
        assertThat(new JwtTokenTypeValidator().validate(jwt("access")).hasErrors()).isFalse();
    }

    @Test
    void rejectsOtherTokenTypes() {
        assertThat(new JwtTokenTypeValidator().validate(jwt("id")).hasErrors()).isTrue();
        assertThat(new JwtTokenTypeValidator().validate(jwt("refresh")).hasErrors()).isTrue();
    }

    @Test
    void rejectsMissingType() {
        assertThat(new JwtTokenTypeValidator().validate(jwt(null)).hasErrors()).isTrue();
    }
}
