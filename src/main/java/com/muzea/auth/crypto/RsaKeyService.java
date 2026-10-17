package com.muzea.auth.crypto;

import com.muzea.auth.config.AuthProperties;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.crypto.RSASSASigner;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

/**
 * Единственная точка доступа к RSA-ключу подписи access-токенов.
 *
 * <p>В prod ключ приходит из {@code AUTH_RSA_PRIVATE_KEY} (base64 PKCS#8) и
 * используется всеми нодами одинаково — так JWKS совпадает между репликами.
 * В dev, если ключ не задан, генерируется эфемерный (токены живут до рестарта).
 */
@Slf4j
@Component
public class RsaKeyService {

    private final RSAKey rsaKey;
    private final RSASSASigner signer;

    public RsaKeyService(AuthProperties properties) {
        this.rsaKey = buildKey(properties.rsa());
        try {
            this.signer = new RSASSASigner(rsaKey);
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to create RSA signer", e);
        }
    }

    private RSAKey buildKey(AuthProperties.Rsa rsa) {
        String keyId = (rsa.keyId() == null || rsa.keyId().isBlank()) ? "primary" : rsa.keyId();
        if (rsa.privateKey() == null || rsa.privateKey().isBlank()) {
            log.warn("auth.rsa.private-key is not set — generating an ephemeral RSA key. "
                    + "Tokens will be invalid after restart. Do NOT use this in production.");
            return generate(keyId);
        }
        return fromPkcs8(rsa.privateKey(), keyId);
    }

    private RSAKey generate(String keyId) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            return toRsaKey((RSAPublicKey) pair.getPublic(), (RSAPrivateKey) pair.getPrivate(), keyId);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA key generation failed", e);
        }
    }

    private RSAKey fromPkcs8(String base64, String keyId) {
        try {
            byte[] der = Base64.getDecoder().decode(base64.trim());
            RSAPrivateKey privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(der));
            return toRsaKey(derivePublic(privateKey), privateKey, keyId);
        } catch (IllegalArgumentException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Invalid AUTH_RSA_PRIVATE_KEY (expected base64 PKCS#8)", e);
        }
    }

    private RSAPublicKey derivePublic(RSAPrivateKey privateKey) {
        try {
            java.security.interfaces.RSAPrivateCrtKey crt = (java.security.interfaces.RSAPrivateCrtKey) privateKey;
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(
                    new java.security.spec.RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("Failed to derive RSA public key", e);
        }
    }

    private RSAKey toRsaKey(RSAPublicKey publicKey, RSAPrivateKey privateKey, String keyId) {
        return new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyID(keyId)
                .build();
    }

    public RSASSASigner signer() {
        return signer;
    }

    public RSAKey rsaKey() {
        return rsaKey;
    }

    /** Публичный ключ для настройки JwtDecoder без проверки исключений на месте вызова. */
    public RSAPublicKey publicKey() {
        try {
            return rsaKey.toRSAPublicKey();
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to extract RSA public key", e);
        }
    }

    public String keyId() {
        return rsaKey.getKeyID();
    }

    /** Публичная часть ключа для JWKS (без приватных параметров). */
    public JWKSet publicJwkSet() {
        return new JWKSet(rsaKey.toPublicJWK());
    }

    /** Случайный идентификатор для jti/refresh-токенов. */
    public static String randomId() {
        return UUID.randomUUID().toString();
    }
}
