package com.muzea.auth.web;

import com.muzea.auth.config.AuthProperties;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class OpenIdConfigurationControllerTest {

    @Test
    void discoveryDocumentPointsToIssuerEndpoints() {
        AuthProperties properties = new AuthProperties(
                "https://auth.muzea.test", List.of("muzea"), 900, 86400, null, null, null);

        Map<String, Object> config = new OpenIdConfigurationController(properties).configuration();

        assertThat(config.get("issuer")).isEqualTo("https://auth.muzea.test");
        assertThat(config.get("jwks_uri")).isEqualTo("https://auth.muzea.test/.well-known/jwks.json");
        assertThat(config.get("token_endpoint")).isEqualTo("https://auth.muzea.test/auth/token/refresh");
        assertThat(config.get("response_types_supported")).isEqualTo(List.of("token"));
        assertThat(config.get("grant_types_supported")).isEqualTo(List.of("refresh_token"));
        assertThat(config.get("subject_types_supported")).isEqualTo(List.of("public"));
        assertThat(config.get("id_token_signing_alg_values_supported")).isEqualTo(List.of("RS256"));
        assertThat(config.get("scopes_supported")).isEqualTo(List.of("openid"));
    }
}
