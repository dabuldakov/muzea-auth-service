package com.muzea.auth.email;

import com.muzea.auth.config.AuthProperties;
import com.muzea.auth.error.AuthException;
import com.muzea.auth.token.TokenHasher;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;

/**
 * Выпуск и проверка одноразовых email-кодов. В БД хранится только хэш кода,
 * у кода ограниченный TTL и число попыток ввода.
 */
@Service
@RequiredArgsConstructor
public class EmailCodeService {

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final EmailCodeRepository repository;
    private final TokenHasher tokenHasher;
    private final MailService mailService;
    private final AuthProperties properties;

    /** Выпускает новый код (инвалидируя прежние) и отправляет его на email. */
    @Transactional
    public void issue(String email, EmailPurpose purpose) {
        repository.deleteByEmailIgnoreCaseAndPurpose(email, purpose);
        String code = generateCode(properties.otp().length());
        EmailCode entity = EmailCode.builder()
                .email(email)
                .purpose(purpose)
                .codeHash(tokenHasher.hash(code))
                .expiresAt(Instant.now().plusSeconds(properties.otp().ttlSeconds()))
                .build();
        repository.save(entity);
        mailService.sendOtp(email, code, purpose);
    }

    /** Проверяет код; при успехе помечает его использованным. */
    @Transactional
    public void verify(String email, EmailPurpose purpose, String code) {
        EmailCode entity = repository
                .findFirstByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(email, purpose)
                .orElseThrow(() -> AuthException.badRequest("otp_not_found", "No active code for this email"));

        if (entity.isExpired(Instant.now())) {
            throw AuthException.badRequest("otp_expired", "Code has expired");
        }
        if (entity.getAttempts() >= properties.otp().maxAttempts()) {
            throw AuthException.tooManyRequests("otp_attempts_exceeded", "Too many attempts, request a new code");
        }
        entity.setAttempts(entity.getAttempts() + 1);
        if (!constantTimeEquals(entity.getCodeHash(), tokenHasher.hash(code))) {
            throw AuthException.badRequest("otp_invalid", "Invalid code");
        }
        entity.setConsumedAt(Instant.now());
    }

    /** Удаляет все коды, выпущенные на email (при удалении аккаунта). */
    @Transactional
    public void deleteForEmail(String email) {
        repository.deleteByEmailIgnoreCase(email);
    }

    private String generateCode(int length) {
        StringBuilder builder = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            builder.append(SECURE_RANDOM.nextInt(10));
        }
        return builder.toString();
    }

    private boolean constantTimeEquals(String expected, String actual) {
        return MessageDigest.isEqual(
                expected.getBytes(StandardCharsets.UTF_8),
                actual.getBytes(StandardCharsets.UTF_8));
    }
}
