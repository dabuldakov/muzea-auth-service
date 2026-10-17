package com.muzea.auth.token;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TokenHasherTest {

    private final TokenHasher hasher = new TokenHasher();

    @Test
    void isDeterministicAndHexEncoded() {
        String first = hasher.hash("secret-value");
        String second = hasher.hash("secret-value");

        assertThat(first).isEqualTo(second);
        assertThat(first).hasSize(64).matches("[0-9a-f]+");
    }

    @Test
    void differentInputsProduceDifferentHashes() {
        assertThat(hasher.hash("a")).isNotEqualTo(hasher.hash("b"));
    }
}
