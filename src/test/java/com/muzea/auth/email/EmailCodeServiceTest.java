package com.muzea.auth.email;

import com.muzea.auth.config.AuthProperties;
import com.muzea.auth.error.AuthException;
import com.muzea.auth.token.TokenHasher;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EmailCodeServiceTest {

    private static final String EMAIL = "user@example.com";

    @Mock
    private EmailCodeRepository repository;

    @Mock
    private MailService mailService;

    @Spy
    private TokenHasher tokenHasher = new TokenHasher();

    @Captor
    private ArgumentCaptor<String> codeCaptor;

    @Captor
    private ArgumentCaptor<EmailCode> entityCaptor;

    private final AuthProperties properties = new AuthProperties("iss", List.of("aud"), 900, 3600,
            new AuthProperties.Rsa("", "kid"),
            new AuthProperties.Otp(6, 600, 3, 60, 5));

    private EmailCodeService service() {
        return new EmailCodeService(repository, tokenHasher, mailService, properties);
    }

    @Test
    void issueGeneratesNumericCodeAndStoresOnlyHash() {
        service().issue(EMAIL, EmailPurpose.REGISTER);

        verify(mailService).sendOtp(eq(EMAIL), codeCaptor.capture(), eq(EmailPurpose.REGISTER));
        verify(repository).save(entityCaptor.capture());

        String code = codeCaptor.getValue();
        EmailCode saved = entityCaptor.getValue();
        assertThat(code).hasSize(6).matches("\\d{6}");
        assertThat(saved.getCodeHash()).isEqualTo(tokenHasher.hash(code));
        assertThat(saved.getCodeHash()).isNotEqualTo(code);
        assertThat(saved.getPurpose()).isEqualTo(EmailPurpose.REGISTER);
    }

    @Test
    void verifyAcceptsCorrectCodeAndConsumesIt() {
        EmailCode stored = storedCode("123456", Instant.now().plusSeconds(300), 0, null);
        when(repository.findFirstByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                EMAIL, EmailPurpose.REGISTER)).thenReturn(Optional.of(stored));

        service().verify(EMAIL, EmailPurpose.REGISTER, "123456");

        assertThat(stored.getConsumedAt()).isNotNull();
    }

    @Test
    void verifyRejectsWrongCodeAndIncrementsAttempts() {
        EmailCode stored = storedCode("123456", Instant.now().plusSeconds(300), 0, null);
        when(repository.findFirstByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                EMAIL, EmailPurpose.REGISTER)).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> service().verify(EMAIL, EmailPurpose.REGISTER, "000000"))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("Invalid code");
        assertThat(stored.getAttempts()).isEqualTo(1);
        assertThat(stored.getConsumedAt()).isNull();
    }

    @Test
    void verifyRejectsExpiredCode() {
        EmailCode stored = storedCode("123456", Instant.now().minusSeconds(1), 0, null);
        when(repository.findFirstByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                EMAIL, EmailPurpose.REGISTER)).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> service().verify(EMAIL, EmailPurpose.REGISTER, "123456"))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("expired");
    }

    @Test
    void verifyRejectsWhenAttemptsExceeded() {
        EmailCode stored = storedCode("123456", Instant.now().plusSeconds(300), 3, null);
        when(repository.findFirstByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                EMAIL, EmailPurpose.REGISTER)).thenReturn(Optional.of(stored));

        assertThatThrownBy(() -> service().verify(EMAIL, EmailPurpose.REGISTER, "123456"))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("Too many attempts");
    }

    @Test
    void verifyFailsWhenNoActiveCode() {
        when(repository.findFirstByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
                EMAIL, EmailPurpose.REGISTER)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service().verify(EMAIL, EmailPurpose.REGISTER, "123456"))
                .isInstanceOf(AuthException.class)
                .hasMessageContaining("No active code");
    }

    private EmailCode storedCode(String code, Instant expiresAt, int attempts, Instant consumedAt) {
        return EmailCode.builder()
                .email(EMAIL)
                .purpose(EmailPurpose.REGISTER)
                .codeHash(tokenHasher.hash(code))
                .expiresAt(expiresAt)
                .attempts(attempts)
                .consumedAt(consumedAt)
                .build();
    }
}
