package com.muzea.auth.service;

import com.muzea.auth.email.EmailCodeService;
import com.muzea.auth.email.EmailPurpose;
import com.muzea.auth.email.OtpRateLimiter;
import com.muzea.auth.token.TokenService;
import com.muzea.auth.user.User;
import com.muzea.auth.user.UserService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserService userService;
    @Mock
    private EmailCodeService emailCodeService;
    @Mock
    private OtpRateLimiter rateLimiter;
    @Mock
    private TokenService tokenService;

    @InjectMocks
    private AuthService authService;

    private User user(String email) {
        return User.builder()
                .id(UUID.randomUUID())
                .email(email)
                .username("user")
                .emailVerified(false)
                .build();
    }

    @Test
    void registerIssuesVerificationCode() {
        User user = user("x@y.z");
        when(userService.register("x@y.z", "user", null)).thenReturn(user);

        authService.register("x@y.z", "user", null);

        verify(rateLimiter).checkAndRecord("x@y.z", EmailPurpose.REGISTER);
        verify(emailCodeService).issue("x@y.z", EmailPurpose.REGISTER);
    }

    @Test
    void requestLoginCodeIsNeutralForUnknownAccount() {
        when(userService.findByEmail("n@n.n")).thenReturn(Optional.empty());

        authService.requestLoginCode("n@n.n");

        verify(rateLimiter).checkAndRecord("n@n.n", EmailPurpose.LOGIN);
        verify(emailCodeService, never()).issue(any(), any());
    }

    @Test
    void requestLoginCodeSkipsUnverifiedAccount() {
        when(userService.findByEmail("u@u.u")).thenReturn(Optional.of(user("u@u.u")));

        authService.requestLoginCode("u@u.u");

        verify(emailCodeService, never()).issue(any(), any());
    }

    @Test
    void deleteAccountDeactivatesSessionsCodesAndUser() {
        UUID id = UUID.randomUUID();
        User user = User.builder()
                .id(id).email("a@b.c").username("a").emailVerified(true).build();
        when(userService.getById(id)).thenReturn(user);

        authService.deleteAccount(id);

        verify(tokenService).deleteAllSessions(id);
        verify(emailCodeService).deleteForEmail("a@b.c");
        verify(userService).deactivate(user);
        verify(userService, never()).delete(any());
    }

    @Test
    void deletedAccountCannotLoginOrRequestCodes() {
        User deleted = User.builder()
                .id(UUID.randomUUID()).email("a@b.c").username("a")
                .emailVerified(true).isDeleted(true).build();
        when(userService.getByEmail("a@b.c")).thenReturn(deleted);
        when(userService.findByEmail("a@b.c")).thenReturn(java.util.Optional.of(deleted));

        org.junit.jupiter.api.Assertions.assertThrows(
                com.muzea.auth.error.AuthException.class,
                () -> authService.verifyLoginCode("a@b.c", "123456",
                        new com.muzea.auth.token.SessionInfo("d", "ua", "ip"))
        );
        authService.requestLoginCode("a@b.c");

        verify(tokenService, never()).issue(any(), any());
        verify(emailCodeService, never()).issue(any(), any());
    }
}
