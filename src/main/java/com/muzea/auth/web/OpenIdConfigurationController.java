package com.muzea.auth.web;

import com.muzea.auth.config.AuthProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Минимальный discovery-документ: сообщает издателя, где взять JWKS и как
 * обновлять токены. Полноценная авторизация (authorization_endpoint) появится,
 * если понадобится веб-клиент.
 */
@RestController
@RequiredArgsConstructor
public class OpenIdConfigurationController {

    private final AuthProperties properties;

    @GetMapping("/.well-known/openid-configuration")
    public Map<String, Object> configuration() {
        Map<String, Object> config = new LinkedHashMap<>();
        config.put("issuer", properties.issuer());
        config.put("jwks_uri", properties.issuer() + "/.well-known/jwks.json");
        config.put("token_endpoint", properties.issuer() + "/auth/token/refresh");
        config.put("response_types_supported", List.of("token"));
        config.put("grant_types_supported", List.of("refresh_token"));
        config.put("subject_types_supported", List.of("public"));
        config.put("id_token_signing_alg_values_supported", List.of("RS256"));
        config.put("scopes_supported", List.of("openid"));
        return config;
    }
}
