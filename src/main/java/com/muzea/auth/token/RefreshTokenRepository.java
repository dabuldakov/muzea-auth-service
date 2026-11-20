package com.muzea.auth.token;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, UUID> {

    /**
     * Блокируем строку на время ротации: два параллельных refresh на разных
     * нодах не должны оба увидеть revoked=false и выдать две новые ветки.
     * Второй ждёт коммита первого, видит revoked=true и срабатывает reuse-detection.
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<RefreshToken> findByTokenHash(String tokenHash);

    List<RefreshToken> findByUserIdAndRevokedFalse(UUID userId);

    List<RefreshToken> findByFamilyId(UUID familyId);

    void deleteByUserId(UUID userId);
}
