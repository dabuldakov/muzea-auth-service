package com.muzea.auth.web;

import com.muzea.auth.user.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;

/**
 * Реактивация аккаунта силами поддержки: только по служебному токену,
 * после письма пользователя.
 */
@Slf4j
@RestController
@RequestMapping("/support/accounts")
public class SupportController {

    private final UserService userService;
    private final String supportToken;

    public SupportController(
            UserService userService,
            @Value("${support.token:}") String supportToken
    ) {
        this.userService = userService;
        this.supportToken = supportToken;
    }

    @PostMapping("/{id}/reactivate")
    public ResponseEntity<Void> reactivate(
            @PathVariable UUID id,
            @RequestHeader(value = "X-Support-Token", required = false) String provided
    ) {
        if (supportToken.isBlank() || provided == null || !MessageDigest.isEqual(
                supportToken.getBytes(StandardCharsets.UTF_8),
                provided.getBytes(StandardCharsets.UTF_8))) {
            log.warn("Reactivation denied: bad support token");
            return ResponseEntity.status(403).build();
        }
        userService.reactivate(id);
        return ResponseEntity.noContent().build();
    }
}
