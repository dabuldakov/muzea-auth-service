package com.muzea.auth.service;

import com.muzea.auth.email.EmailCodeService;
import com.muzea.auth.email.EmailPurpose;
import com.muzea.auth.email.OtpRateLimiter;
import com.muzea.auth.token.IssuedTokens;
import com.muzea.auth.token.RefreshToken;
import com.muzea.auth.token.SessionInfo;
import com.muzea.auth.token.TokenService;
import com.muzea.auth.user.User;
import com.muzea.auth.user.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Оркестрация регистрации и входа: связывает пользователей, email-коды и токены.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserService userService;
    private final EmailCodeService emailCodeService;
    private final OtpRateLimiter rateLimiter;
    private final TokenService tokenService;

    /** Регистрация: создаёт неверифицированного пользователя и шлёт код. */
    @Transactional
    public void register(String email, String username, String displayName) {
        User user = userService.register(email, username, displayName);
        rateLimiter.checkAndRecord(user.getEmail(), EmailPurpose.REGISTER);
        emailCodeService.issue(user.getEmail(), EmailPurpose.REGISTER);
    }

    /** Подтверждение email: проверяет код, активирует аккаунт и выдаёт токены. */
    @Transactional
    public IssuedTokens verifyEmail(String email, String code, SessionInfo session) {
        User user = userService.getByEmail(email);
        requireActive(user);
        emailCodeService.verify(user.getEmail(), EmailPurpose.REGISTER, code);
        userService.markEmailVerified(user);
        return tokenService.issue(user, session);
    }

    /** Повторная отправка кода подтверждения. Нейтрально к наличию аккаунта. */
    public void resendVerification(String email) {
        rateLimiter.checkAndRecord(email, EmailPurpose.REGISTER);
        userService.findByEmail(email)
                .filter(user -> !user.isDeleted() && !user.isEmailVerified())
                .ifPresent(user -> emailCodeService.issue(user.getEmail(), EmailPurpose.REGISTER));
    }

    /** Почему письмо с кодом входа не ушло (или ушло). */
    public enum LoginCodeStatus {
        SENT,
        NOT_FOUND,
        UNVERIFIED,
        DELETED
    }

    /**
     * Запрос кода для входа. Клиенту возвращается статус, чтобы показать
     * «такой email не зарегистрирован» вместо молчаливого «код отправлен».
     * Текст ответа остаётся нейтральным для совместимости со старыми клиентами.
     */
    public LoginCodeStatus requestLoginCode(String email) {
        rateLimiter.checkAndRecord(email, EmailPurpose.LOGIN);
        var found = userService.findByEmail(email);
        if (found.isEmpty()) {
            log.info("Login OTP skipped: no account for {}", mask(email));
            return LoginCodeStatus.NOT_FOUND;
        }
        User user = found.get();
        if (user.isDeleted()) {
            log.info("Login OTP skipped: account deactivated for {}", mask(email));
            return LoginCodeStatus.DELETED;
        }
        if (!user.isEmailVerified()) {
            log.info("Login OTP skipped: email not verified for {}", mask(email));
            return LoginCodeStatus.UNVERIFIED;
        }
        emailCodeService.issue(user.getEmail(), EmailPurpose.LOGIN);
        return LoginCodeStatus.SENT;
    }

    private static String mask(String email) {
        if (email == null || email.isBlank()) {
            return "<empty>";
        }
        int at = email.indexOf('@');
        if (at <= 0) {
            return "***";
        }
        String local = email.substring(0, at);
        String visible = local.length() <= 2 ? local.substring(0, 1) : local.substring(0, 2);
        return visible + "***" + email.substring(at);
    }

    /** Вход по коду: проверяет код и выдаёт токены. */
    @Transactional
    public IssuedTokens verifyLoginCode(String email, String code, SessionInfo session) {
        User user = userService.getByEmail(email);
        requireActive(user);
        emailCodeService.verify(user.getEmail(), EmailPurpose.LOGIN, code);
        return tokenService.issue(user, session);
    }

    public IssuedTokens refresh(String refreshToken, SessionInfo session) {
        return tokenService.rotate(refreshToken, session);
    }

    public void logout(String refreshToken) {
        tokenService.revoke(refreshToken);
    }

    public void logoutAll(UUID userId) {
        tokenService.revokeAll(userId);
    }

    public void revokeSession(UUID userId, UUID sessionId) {
        tokenService.revokeSession(userId, sessionId);
    }

    public List<RefreshToken> activeSessions(UUID userId) {
        return tokenService.activeSessions(userId);
    }

    public User currentUser(UUID userId) {
        User user = userService.getById(userId);
        requireActive(user);
        return user;
    }

    private void requireActive(User user) {
        if (user.isDeleted()) {
            throw com.muzea.auth.error.AuthException.unauthorized(
                    "account_deleted", "Account is deactivated");
        }
    }

    /**
     * Удаление аккаунта в IdP = деактивация: сессии и коды убираем, вход
     * закрываем, но строку с email и username оставляем для реактивации.
     */
    @Transactional
    public void deleteAccount(UUID userId) {
        User user = userService.getById(userId);
        tokenService.deleteAllSessions(userId);
        emailCodeService.deleteForEmail(user.getEmail());
        userService.deactivate(user);
    }
}
