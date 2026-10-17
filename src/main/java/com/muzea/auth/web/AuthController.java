package com.muzea.auth.web;

import com.muzea.auth.security.IpRateLimiter;
import com.muzea.auth.service.AuthService;
import com.muzea.auth.token.IssuedTokens;
import com.muzea.auth.token.RefreshToken;
import com.muzea.auth.token.SessionInfo;
import com.muzea.auth.user.User;
import com.muzea.auth.web.dto.AuthDtos;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final IpRateLimiter ipRateLimiter;

    @PostMapping("/register")
    public AuthDtos.MessageResponse register(@Valid @RequestBody AuthDtos.RegisterRequest request,
                                             HttpServletRequest httpRequest) {
        ipRateLimiter.checkAndRecord(clientIp(httpRequest));
        authService.register(request.email(), request.username(), request.displayName());
        return new AuthDtos.MessageResponse("Verification code sent");
    }

    @PostMapping("/verify-email")
    public AuthDtos.TokenResponse verifyEmail(@Valid @RequestBody AuthDtos.VerifyEmailRequest request,
                                              HttpServletRequest httpRequest) {
        ipRateLimiter.checkAndRecord(clientIp(httpRequest));
        IssuedTokens issued = authService.verifyEmail(request.email(), request.code(),
                session(request.deviceId(), httpRequest));
        return toTokenResponse(issued);
    }

    @PostMapping("/resend-verification")
    public AuthDtos.MessageResponse resendVerification(
            @Valid @RequestBody AuthDtos.ResendVerificationRequest request,
            HttpServletRequest httpRequest) {
        ipRateLimiter.checkAndRecord(clientIp(httpRequest));
        authService.resendVerification(request.email());
        return new AuthDtos.MessageResponse("If the account exists, a code has been sent");
    }

    @PostMapping("/otp/request")
    public AuthDtos.MessageResponse requestLoginCode(@Valid @RequestBody AuthDtos.OtpRequest request,
                                                     HttpServletRequest httpRequest) {
        ipRateLimiter.checkAndRecord(clientIp(httpRequest));
        authService.requestLoginCode(request.email());
        return new AuthDtos.MessageResponse("If the account exists, a code has been sent");
    }

    @PostMapping("/otp/verify")
    public AuthDtos.TokenResponse verifyLoginCode(@Valid @RequestBody AuthDtos.OtpVerifyRequest request,
                                                  HttpServletRequest httpRequest) {
        ipRateLimiter.checkAndRecord(clientIp(httpRequest));
        IssuedTokens issued = authService.verifyLoginCode(request.email(), request.code(),
                session(request.deviceId(), httpRequest));
        return toTokenResponse(issued);
    }

    @PostMapping("/token/refresh")
    public AuthDtos.TokenResponse refresh(@Valid @RequestBody AuthDtos.RefreshRequest request,
                                          HttpServletRequest httpRequest) {
        IssuedTokens issued = authService.refresh(request.refreshToken(),
                session(request.deviceId(), httpRequest));
        return toTokenResponse(issued);
    }

    @PostMapping("/logout")
    public AuthDtos.MessageResponse logout(@Valid @RequestBody AuthDtos.LogoutRequest request) {
        authService.logout(request.refreshToken());
        return new AuthDtos.MessageResponse("Logged out");
    }

    @PostMapping("/logout-all")
    public AuthDtos.MessageResponse logoutAll(@AuthenticationPrincipal Jwt jwt) {
        authService.logoutAll(userId(jwt));
        return new AuthDtos.MessageResponse("Logged out from all devices");
    }

    @GetMapping("/me")
    public AuthDtos.UserResponse me(@AuthenticationPrincipal Jwt jwt) {
        return toUserResponse(authService.currentUser(userId(jwt)));
    }

    @DeleteMapping("/me")
    public AuthDtos.MessageResponse deleteMe(@AuthenticationPrincipal Jwt jwt) {
        authService.deleteAccount(userId(jwt));
        return new AuthDtos.MessageResponse("Account deleted");
    }

    @GetMapping("/sessions")
    public List<AuthDtos.SessionResponse> sessions(@AuthenticationPrincipal Jwt jwt) {
        return authService.activeSessions(userId(jwt)).stream()
                .map(AuthController::toSessionResponse)
                .toList();
    }

    @DeleteMapping("/sessions/{id}")
    public AuthDtos.MessageResponse revokeSession(@AuthenticationPrincipal Jwt jwt,
                                                  @PathVariable UUID id) {
        authService.revokeSession(userId(jwt), id);
        return new AuthDtos.MessageResponse("Session revoked");
    }

    private static UUID userId(Jwt jwt) {
        return UUID.fromString(jwt.getSubject());
    }

    private static AuthDtos.TokenResponse toTokenResponse(IssuedTokens issued) {
        return new AuthDtos.TokenResponse(
                issued.tokens().accessToken(),
                issued.tokens().refreshToken(),
                "Bearer",
                issued.tokens().accessExpiresInSeconds(),
                toUserResponse(issued.user()));
    }

    private static AuthDtos.UserResponse toUserResponse(User user) {
        return new AuthDtos.UserResponse(user.getId(), user.getEmail(), user.getUsername(),
                user.getDisplayName(), user.isEmailVerified());
    }

    private static AuthDtos.SessionResponse toSessionResponse(RefreshToken token) {
        return new AuthDtos.SessionResponse(token.getId(), token.getDeviceId(), token.getUserAgent(),
                token.getIp(), token.getCreatedAt(), token.getLastUsedAt());
    }

    private static SessionInfo session(String deviceId, HttpServletRequest request) {
        return new SessionInfo(deviceId, request.getHeader("User-Agent"), clientIp(request));
    }

    private static String clientIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
