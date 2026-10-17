package com.muzea.auth.token;

import com.muzea.auth.config.AuthProperties;
import com.muzea.auth.crypto.RsaKeyService;
import com.muzea.auth.error.AuthException;
import com.muzea.auth.user.User;
import com.muzea.auth.user.UserRepository;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/**
 * Выдача и ротация токенов.
 *
 * <ul>
 *   <li>access — JWT RS256 (короткоживущий), проверяется ресурс-сервисами по JWKS;</li>
 *   <li>refresh — непрозрачный секрет, хранится хэшем, одноразовый, с ротацией
 *       и обнаружением повторного использования.</li>
 * </ul>
 */
@Service
@RequiredArgsConstructor
public class TokenService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();
    private static final int REFRESH_TOKEN_BYTES = 32;

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final TokenHasher tokenHasher;
    private final RsaKeyService rsaKeyService;
    private final AuthProperties properties;

    /** Новый вход: создаёт пару токенов и новое семейство refresh. */
    @Transactional
    public IssuedTokens issue(User user, SessionInfo session) {
        UUID familyId = UUID.randomUUID();
        String refresh = persistRefresh(user.getId(), familyId, null, session);
        TokenPair pair = new TokenPair(createAccessToken(user), refresh, properties.accessTokenTtlSeconds());
        return new IssuedTokens(pair, user);
    }

    /**
     * Ротация refresh-токена. Повторное использование уже отозванного токена
     * трактуется как кража — отзывается всё семейство.
     */
    @Transactional
    public IssuedTokens rotate(String rawRefreshToken, SessionInfo session) {
        RefreshToken stored = refreshTokenRepository.findByTokenHash(tokenHasher.hash(rawRefreshToken))
                .orElseThrow(() -> AuthException.unauthorized("invalid_refresh_token", "Refresh token is invalid"));

        Instant now = Instant.now();
        if (stored.isRevoked()) {
            revokeFamily(stored.getFamilyId());
            throw AuthException.unauthorized("refresh_token_reused", "Refresh token reuse detected");
        }
        if (stored.isExpired(now)) {
            stored.setRevoked(true);
            throw AuthException.unauthorized("refresh_token_expired", "Refresh token has expired");
        }

        User user = userRepository.findById(stored.getUserId())
                .orElseThrow(() -> AuthException.unauthorized("user_not_found", "User no longer exists"));

        stored.setRevoked(true);
        stored.setLastUsedAt(now);

        String next = persistRefresh(stored.getUserId(), stored.getFamilyId(), stored.getId(), session);
        TokenPair pair = new TokenPair(createAccessToken(user), next, properties.accessTokenTtlSeconds());
        return new IssuedTokens(pair, user);
    }

    @Transactional
    public void revoke(String rawRefreshToken) {
        refreshTokenRepository.findByTokenHash(tokenHasher.hash(rawRefreshToken)).ifPresent(token -> {
            token.setRevoked(true);
            token.setLastUsedAt(Instant.now());
        });
    }

    @Transactional
    public void revokeAll(UUID userId) {
        for (RefreshToken token : refreshTokenRepository.findByUserIdAndRevokedFalse(userId)) {
            token.setRevoked(true);
        }
    }

    /** Полное удаление refresh-сессий пользователя (при удалении аккаунта). */
    @Transactional
    public void deleteAllSessions(UUID userId) {
        refreshTokenRepository.deleteByUserId(userId);
    }

    @Transactional
    public void revokeSession(UUID userId, UUID sessionId) {
        refreshTokenRepository.findById(sessionId)
                .filter(token -> token.getUserId().equals(userId))
                .ifPresent(token -> token.setRevoked(true));
    }

    @Transactional(readOnly = true)
    public List<RefreshToken> activeSessions(UUID userId) {
        return refreshTokenRepository.findByUserIdAndRevokedFalse(userId);
    }

    public String createAccessToken(User user) {
        Instant now = Instant.now();
        Instant exp = now.plusSeconds(properties.accessTokenTtlSeconds());
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .issuer(properties.issuer())
                .subject(user.getId().toString())
                .audience(properties.audience())
                .claim("email", user.getEmail())
                .claim("username", user.getUsername())
                .claim("type", "access")
                .jwtID(RsaKeyService.randomId())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(exp))
                .build();
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID(rsaKeyService.keyId())
                .build();
        SignedJWT jwt = new SignedJWT(header, claims);
        try {
            jwt.sign(rsaKeyService.signer());
        } catch (JOSEException e) {
            throw new IllegalStateException("Failed to sign access token", e);
        }
        return jwt.serialize();
    }

    private String persistRefresh(UUID userId, UUID familyId, UUID rotatedFrom, SessionInfo session) {
        String raw = randomToken();
        RefreshToken token = RefreshToken.builder()
                .userId(userId)
                .familyId(familyId)
                .deviceId(session.deviceId())
                .tokenHash(tokenHasher.hash(raw))
                .expiresAt(Instant.now().plusSeconds(properties.refreshTokenTtlSeconds()))
                .rotatedFrom(rotatedFrom)
                .userAgent(session.userAgent())
                .ip(session.ip())
                .build();
        refreshTokenRepository.save(token);
        return raw;
    }

    private void revokeFamily(UUID familyId) {
        for (RefreshToken token : refreshTokenRepository.findByFamilyId(familyId)) {
            token.setRevoked(true);
        }
    }

    private String randomToken() {
        byte[] bytes = new byte[REFRESH_TOKEN_BYTES];
        SECURE_RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
