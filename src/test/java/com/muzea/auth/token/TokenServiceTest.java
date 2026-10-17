package com.muzea.auth.token;

import com.muzea.auth.config.AuthProperties;
import com.muzea.auth.crypto.RsaKeyService;
import com.muzea.auth.error.AuthException;
import com.muzea.auth.user.User;
import com.muzea.auth.user.UserRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TokenServiceTest {

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private UserRepository userRepository;

    private final TokenHasher tokenHasher = new TokenHasher();
    private final RsaKeyService rsaKeyService = new RsaKeyService(properties());
    private final AuthProperties properties = properties();

    private TokenService tokenService;

    @BeforeEach
    void setUp() {
        tokenService = new TokenService(refreshTokenRepository, userRepository, tokenHasher,
                rsaKeyService, properties);
    }

    private static AuthProperties properties() {
        return new AuthProperties("https://auth.muzea.su", List.of("api-muzea", "chat-muzea"),
                900, 2592000,
                new AuthProperties.Rsa("", "primary"),
                new AuthProperties.Otp(6, 600, 5, 60, 5));
    }

    private User user() {
        return User.builder()
                .id(UUID.randomUUID())
                .email("user@example.com")
                .username("user")
                .emailVerified(true)
                .build();
    }

    @Test
    void issueProducesSignedAccessTokenAndPersistsRefreshToken() throws Exception {
        User user = user();
        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);

        IssuedTokens issued = tokenService.issue(user, new SessionInfo("device-1", "agent", "127.0.0.1"));

        verify(refreshTokenRepository).save(captor.capture());
        RefreshToken stored = captor.getValue();

        SignedJWT jwt = SignedJWT.parse(issued.tokens().accessToken());
        assertThat(jwt.getHeader().getAlgorithm()).isEqualTo(JWSAlgorithm.RS256);
        assertThat(jwt.verify(new RSASSAVerifier(rsaKeyService.publicKey()))).isTrue();
        assertThat(jwt.getJWTClaimsSet().getSubject()).isEqualTo(user.getId().toString());
        assertThat(jwt.getJWTClaimsSet().getIssuer()).isEqualTo("https://auth.muzea.su");
        assertThat(jwt.getJWTClaimsSet().getAudience()).contains("api-muzea", "chat-muzea");

        assertThat(stored.getTokenHash()).isEqualTo(tokenHasher.hash(issued.tokens().refreshToken()));
        assertThat(stored.getUserId()).isEqualTo(user.getId());
        assertThat(stored.getDeviceId()).isEqualTo("device-1");
    }

    @Test
    void rotateIssuesNewTokensAndRevokesOldOne() {
        User user = user();
        IssuedTokens first = tokenService.issue(user, new SessionInfo("device-1", "agent", "ip"));
        RefreshToken stored = captureSavedToken();

        when(refreshTokenRepository.findByTokenHash(tokenHasher.hash(first.tokens().refreshToken())))
                .thenReturn(Optional.of(stored));
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));

        IssuedTokens rotated = tokenService.rotate(first.tokens().refreshToken(),
                new SessionInfo("device-1", "agent", "ip"));

        assertThat(rotated.tokens().refreshToken()).isNotEqualTo(first.tokens().refreshToken());
        assertThat(stored.isRevoked()).isTrue();
    }

    @Test
    void rotateDetectsReuseAndRevokesFamily() {
        User user = user();
        IssuedTokens first = tokenService.issue(user, new SessionInfo("device-1", "agent", "ip"));
        RefreshToken stored = captureSavedToken();
        stored.setRevoked(true);
        when(refreshTokenRepository.findByTokenHash(tokenHasher.hash(first.tokens().refreshToken())))
                .thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> tokenService.rotate(first.tokens().refreshToken(),
                new SessionInfo("device-1", "agent", "ip")))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("reuse");
        verify(refreshTokenRepository).findByFamilyId(stored.getFamilyId());
    }

    @Test
    void rotateRejectsExpiredToken() {
        User user = user();
        IssuedTokens first = tokenService.issue(user, new SessionInfo("device-1", "agent", "ip"));
        RefreshToken stored = captureSavedToken();
        stored.setExpiresAt(Instant.now().minusSeconds(10));
        when(refreshTokenRepository.findByTokenHash(tokenHasher.hash(first.tokens().refreshToken())))
                .thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> tokenService.rotate(first.tokens().refreshToken(),
                new SessionInfo("device-1", "agent", "ip")))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("expired");
        assertThat(stored.isRevoked()).isTrue();
    }

    @Test
    void rotateRejectsUnknownToken() {
        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> tokenService.rotate("unknown", new SessionInfo(null, null, null)))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("invalid");
    }

    private RefreshToken captureSavedToken() {
        ArgumentCaptor<RefreshToken> captor = ArgumentCaptor.forClass(RefreshToken.class);
        verify(refreshTokenRepository).save(captor.capture());
        return captor.getValue();
    }
}
