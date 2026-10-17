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
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/**
 * Оркестрация регистрации и входа: связывает пользователей, email-коды и токены.
 */
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
        emailCodeService.verify(user.getEmail(), EmailPurpose.REGISTER, code);
        userService.markEmailVerified(user);
        return tokenService.issue(user, session);
    }

    /** Повторная отправка кода подтверждения. Нейтрально к наличию аккаунта. */
    public void resendVerification(String email) {
        rateLimiter.checkAndRecord(email, EmailPurpose.REGISTER);
        userService.findByEmail(email)
                .filter(user -> !user.isEmailVerified())
                .ifPresent(user -> emailCodeService.issue(user.getEmail(), EmailPurpose.REGISTER));
    }

    /** Запрос кода для входа. Ответ нейтрален, чтобы не раскрывать наличие email. */
    public void requestLoginCode(String email) {
        rateLimiter.checkAndRecord(email, EmailPurpose.LOGIN);
        userService.findByEmail(email)
                .filter(User::isEmailVerified)
                .ifPresent(user -> emailCodeService.issue(user.getEmail(), EmailPurpose.LOGIN));
    }

    /** Вход по коду: проверяет код и выдаёт токены. */
    @Transactional
    public IssuedTokens verifyLoginCode(String email, String code, SessionInfo session) {
        User user = userService.getByEmail(email);
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
        return userService.getById(userId);
    }

    /** Полное удаление аккаунта в IdP: сессии, коды и сам пользователь. */
    @Transactional
    public void deleteAccount(UUID userId) {
        User user = userService.getById(userId);
        tokenService.deleteAllSessions(userId);
        emailCodeService.deleteForEmail(user.getEmail());
        userService.delete(userId);
    }
}
