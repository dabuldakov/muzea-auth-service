package com.muzea.auth.crypto;

import com.muzea.auth.config.AuthProperties;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RsaKeyServiceTest {

    private AuthProperties properties(String privateKey) {
        return new AuthProperties("https://auth.muzea.su", List.of("api-muzea"),
                900, 3600,
                new AuthProperties.Rsa(privateKey, "kid-1"),
                new AuthProperties.Otp(6, 600, 5, 60, 5),
                new AuthProperties.RateLimit(60, 1));
    }

    @Test
    void generatesEphemeralKeyWhenNotConfigured() {
        RsaKeyService service = new RsaKeyService(properties(""));

        assertThat(service.keyId()).isEqualTo("kid-1");
        assertThat(service.publicKey()).isNotNull();
        assertThat(service.publicJwkSet().getKeys()).hasSize(1);
    }

    @Test
    void loadsConfiguredPkcs8Key() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        KeyPair pair = generator.generateKeyPair();
        String base64Pkcs8 = Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded());

        RsaKeyService service = new RsaKeyService(properties(base64Pkcs8));

        assertThat(service.publicKey().getModulus())
                .isEqualTo(((java.security.interfaces.RSAPublicKey) pair.getPublic()).getModulus());
        assertThat(service.signer()).isNotNull();
    }

    @Test
    void rejectsInvalidConfiguredKey() {
        assertThatThrownBy(() -> new RsaKeyService(properties("not-a-key")))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("AUTH_RSA_PRIVATE_KEY");
    }
}
