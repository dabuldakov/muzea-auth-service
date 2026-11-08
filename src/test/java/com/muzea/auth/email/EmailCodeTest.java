package com.muzea.auth.email;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class EmailCodeTest {

    private EmailCode code() {
        return EmailCode.builder()
                .email("user@muzea.test")
                .purpose(EmailPurpose.LOGIN)
                .codeHash("hash")
                .expiresAt(Instant.now().plusSeconds(600))
                .build();
    }

    @Test
    void onCreateFillsIdAndTimestampOnlyOnce() {
        EmailCode code = code();
        code.onCreate();

        assertThat(code.getId()).isNotNull();
        assertThat(code.getCreatedAt()).isNotNull();

        UUID id = code.getId();
        code.onCreate();

        assertThat(code.getId()).isEqualTo(id);
    }

    @Test
    void consumedAndExpiredFlags() {
        EmailCode code = code();

        assertThat(code.isConsumed()).isFalse();
        assertThat(code.isExpired(Instant.now())).isFalse();

        code.setConsumedAt(Instant.now());
        assertThat(code.isConsumed()).isTrue();
        assertThat(code.isExpired(Instant.now().plusSeconds(601))).isTrue();
    }
}
