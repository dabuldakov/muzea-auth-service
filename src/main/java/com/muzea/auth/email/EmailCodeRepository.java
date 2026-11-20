package com.muzea.auth.email;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;

import java.util.Optional;
import java.util.UUID;

public interface EmailCodeRepository extends JpaRepository<EmailCode, UUID> {

    /**
     * Блокируем активный код на время проверки: два параллельных verify не
     * должны оба погасить один код. Второй ждёт коммита и видит consumed_at.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<EmailCode> findFirstByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
            String email, EmailPurpose purpose);

    void deleteByEmailIgnoreCaseAndPurpose(String email, EmailPurpose purpose);

    void deleteByEmailIgnoreCase(String email);
}
