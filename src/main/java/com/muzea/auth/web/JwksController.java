package com.muzea.auth.web;

import com.muzea.auth.crypto.RsaKeyService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** Публичный набор ключей подписи — ресурс-сервисы проверяют им access-токены. */
@RestController
@RequiredArgsConstructor
public class JwksController {

    private final RsaKeyService rsaKeyService;

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        return rsaKeyService.publicJwkSet().toJSONObject();
    }
}
