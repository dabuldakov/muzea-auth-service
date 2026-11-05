package com.muzea.auth.security;

import com.muzea.auth.config.AuthProperties;
import com.muzea.auth.crypto.RsaKeyService;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Проверка реального JwtDecoder: подпись, issuer, audience, срок и тип токена.
 * Все негативные сценарии должны отбрасываться до попадания в контроллер.
 */
class JwtConfigTest {

    private final AuthProperties properties = new AuthProperties(
            "https://auth.muzea.su", List.of("api-muzea", "chat-muzea"),
            900, 3600,
            new AuthProperties.Rsa("", "kid"),
            new AuthProperties.Otp(6, 600, 5, 60, 5),
            new AuthProperties.RateLimit(60, 1)
    );
    private final RsaKeyService rsa = new RsaKeyService(properties);
    private final JwtDecoder decoder = new JwtConfig().jwtDecoder(rsa, properties);

    private String token(String issuer, List<String> audience, Instant expiresAt, String type)
            throws Exception {
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(UUID.randomUUID().toString())
                .issueTime(Date.from(Instant.now().minusSeconds(5)))
                .expirationTime(Date.from(expiresAt));
        if (audience != null) {
            builder.audience(audience);
        }
        if (type != null) {
            builder.claim("type", type);
        }
        SignedJWT jwt = new SignedJWT(
                new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(rsa.keyId()).build(),
                builder.build()
        );
        jwt.sign(rsa.signer());
        return jwt.serialize();
    }

    private String validToken() throws Exception {
        return token(properties.issuer(), properties.audience(),
                Instant.now().plusSeconds(60), "access");
    }

    @Test
    void acceptsValidAccessToken() throws Exception {
        Jwt jwt = decoder.decode(validToken());

        assertThat(jwt.getSubject()).isNotBlank();
        assertThat(jwt.getClaimAsString("type")).isEqualTo("access");
    }

    @Test
    void rejectsExpiredToken() throws Exception {
        String expired = token(properties.issuer(), properties.audience(),
                Instant.now().minusSeconds(3600), "access");

        assertThatThrownBy(() -> decoder.decode(expired)).isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsWrongIssuer() throws Exception {
        String wrongIssuer = token("https://evil.example", properties.audience(),
                Instant.now().plusSeconds(60), "access");

        assertThatThrownBy(() -> decoder.decode(wrongIssuer)).isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsWrongAudience() throws Exception {
        String wrongAudience = token(properties.issuer(), List.of("other-service"),
                Instant.now().plusSeconds(60), "access");

        assertThatThrownBy(() -> decoder.decode(wrongAudience)).isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsNonAccessToken() throws Exception {
        String idToken = token(properties.issuer(), properties.audience(),
                Instant.now().plusSeconds(60), "id");

        assertThatThrownBy(() -> decoder.decode(idToken)).isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsTokenWithoutType() throws Exception {
        String untyped = token(properties.issuer(), properties.audience(),
                Instant.now().plusSeconds(60), null);

        assertThatThrownBy(() -> decoder.decode(untyped)).isInstanceOf(JwtException.class);
    }

    @Test
    void rejectsTamperedSignature() throws Exception {
        String valid = validToken();
        char last = valid.charAt(valid.length() - 1);
        String tampered = valid.substring(0, valid.length() - 1) + (last == 'A' ? 'B' : 'A');

        assertThatThrownBy(() -> decoder.decode(tampered)).isInstanceOf(JwtException.class);
    }
}
