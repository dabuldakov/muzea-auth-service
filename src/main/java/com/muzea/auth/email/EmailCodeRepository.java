package com.muzea.auth.email;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface EmailCodeRepository extends JpaRepository<EmailCode, UUID> {

    Optional<EmailCode> findFirstByEmailIgnoreCaseAndPurposeAndConsumedAtIsNullOrderByCreatedAtDesc(
            String email, EmailPurpose purpose);

    void deleteByEmailIgnoreCaseAndPurpose(String email, EmailPurpose purpose);
}
