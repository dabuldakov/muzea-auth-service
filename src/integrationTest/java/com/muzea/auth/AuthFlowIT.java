package com.muzea.auth;

import com.muzea.auth.email.EmailPurpose;
import com.muzea.auth.email.MailService;
import com.muzea.auth.web.dto.AuthDtos;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.ArgumentCaptor.forClass;
import org.mockito.ArgumentCaptor;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureTestRestTemplate
@Testcontainers
class AuthFlowIT {

    private static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:17");

    static {
        POSTGRES.start();
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        // Тесты шлют много запросов с одного IP — снимаем лимит, чтобы не ловить 429.
        registry.add("auth.rate-limit.per-ip-hourly", () -> "100000");
        registry.add("auth.rate-limit.ip-cooldown-seconds", () -> "0");
        registry.add("auth.otp.request-cooldown-seconds", () -> "0");
    }

    @Autowired
    private TestRestTemplate rest;

    @MockitoBean
    private MailService mailService;

    @Test
    void registerVerifyLoginRefreshFlow() {
        String email = "flow@example.com";

        assertThat(postStatus("/auth/register",
                new AuthDtos.RegisterRequest(email, "flowuser", "Flow User")))
                .isEqualTo(HttpStatus.OK);
        String registerCode = capturedCode(email, EmailPurpose.REGISTER);

        ResponseEntity<AuthDtos.TokenResponse> verified = post("/auth/verify-email",
                new AuthDtos.VerifyEmailRequest(email, registerCode, "device-1"), null, AuthDtos.TokenResponse.class);
        assertThat(verified.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(verified.getBody()).isNotNull();
        assertThat(verified.getBody().user().emailVerified()).isTrue();
        String accessToken = verified.getBody().accessToken();
        String refreshToken = verified.getBody().refreshToken();

        ResponseEntity<AuthDtos.UserResponse> me = get("/auth/me", accessToken, AuthDtos.UserResponse.class);
        assertThat(me.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(me.getBody().username()).isEqualTo("flowuser");

        // passwordless login via email OTP
        assertThat(postStatus("/auth/otp/request", new AuthDtos.OtpRequest(email)))
                .isEqualTo(HttpStatus.OK);
        String loginCode = capturedCode(email, EmailPurpose.LOGIN);
        ResponseEntity<AuthDtos.TokenResponse> loggedIn = post("/auth/otp/verify",
                new AuthDtos.OtpVerifyRequest(email, loginCode, "device-2", null), null,
                AuthDtos.TokenResponse.class);
        assertThat(loggedIn.getStatusCode()).isEqualTo(HttpStatus.OK);

        // refresh rotates the token
        ResponseEntity<AuthDtos.TokenResponse> refreshed = post("/auth/token/refresh",
                new AuthDtos.RefreshRequest(refreshToken, "device-1"), null, AuthDtos.TokenResponse.class);
        assertThat(refreshed.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(refreshed.getBody().accessToken()).isNotBlank();

        // the already-used refresh token is rejected (reuse)
        assertThat(postStatus("/auth/token/refresh",
                new AuthDtos.RefreshRequest(refreshToken, "device-1")))
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void verifyEmailRejectsWrongCode() {
        String email = "wrong-code@example.com";
        postStatus("/auth/register", new AuthDtos.RegisterRequest(email, "wrongcode", null));

        ResponseEntity<AuthDtos.ApiError> response = post("/auth/verify-email",
                new AuthDtos.VerifyEmailRequest(email, "000000", null), null, AuthDtos.ApiError.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody().code()).isEqualTo("otp_invalid");
    }

    @Test
    void registerRejectsDuplicateEmail() {
        String email = "duplicate@example.com";
        postStatus("/auth/register", new AuthDtos.RegisterRequest(email, "dupuser", null));

        ResponseEntity<AuthDtos.ApiError> response = post("/auth/register",
                new AuthDtos.RegisterRequest(email, "dupuser2", null), null, AuthDtos.ApiError.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(response.getBody().code()).isEqualTo("email_taken");
    }

    @Test
    void deleteAccountRemovesUser() {
        String email = "delete-me@example.com";
        postStatus("/auth/register", new AuthDtos.RegisterRequest(email, "deleteme", null));
        String code = capturedCode(email, EmailPurpose.REGISTER);
        ResponseEntity<AuthDtos.TokenResponse> verified = post("/auth/verify-email",
                new AuthDtos.VerifyEmailRequest(email, code, "d1"), null, AuthDtos.TokenResponse.class);
        String access = verified.getBody().accessToken();

        ResponseEntity<AuthDtos.MessageResponse> deleted = rest.exchange("/auth/me",
                HttpMethod.DELETE, new HttpEntity<>(headers(access)), AuthDtos.MessageResponse.class);
        assertThat(deleted.getStatusCode()).isEqualTo(HttpStatus.OK);

        // Аккаунта больше нет: /auth/me не находит пользователя.
        assertThat(get("/auth/me", access, AuthDtos.ApiError.class).getStatusCode())
                .isIn(HttpStatus.UNAUTHORIZED, HttpStatus.NOT_FOUND);
    }

    @Test
    void jwksIsPublic() {        ResponseEntity<Map> response = rest.getForEntity("/.well-known/jwks.json", Map.class);
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).containsKey("keys");
    }

    @Test
    void protectedEndpointRequiresToken() {
        assertThat(get("/auth/me", null, AuthDtos.ApiError.class).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(get("/auth/sessions", null, AuthDtos.ApiError.class).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void logoutRevokesRefreshToken() {
        String email = "logout@example.com";
        postStatus("/auth/register", new AuthDtos.RegisterRequest(email, "logoutuser", null));
        String code = capturedCode(email, EmailPurpose.REGISTER);
        AuthDtos.TokenResponse tokens = post("/auth/verify-email",
                new AuthDtos.VerifyEmailRequest(email, code, "d1"), null,
                AuthDtos.TokenResponse.class).getBody();

        assertThat(postStatus("/auth/logout",
                new AuthDtos.LogoutRequest(tokens.refreshToken()))).isEqualTo(HttpStatus.OK);
        assertThat(postStatus("/auth/token/refresh",
                new AuthDtos.RefreshRequest(tokens.refreshToken(), "d1")))
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void sessionsAreListedAndCanBeRevoked() {
        String email = "sessions@example.com";
        postStatus("/auth/register", new AuthDtos.RegisterRequest(email, "sessionsuser", null));
        String registerCode = capturedCode(email, EmailPurpose.REGISTER);
        AuthDtos.TokenResponse first = post("/auth/verify-email",
                new AuthDtos.VerifyEmailRequest(email, registerCode, "d1"), null,
                AuthDtos.TokenResponse.class).getBody();

        postStatus("/auth/otp/request", new AuthDtos.OtpRequest(email));
        String loginCode = capturedCode(email, EmailPurpose.LOGIN);
        AuthDtos.TokenResponse second = post("/auth/otp/verify",
                new AuthDtos.OtpVerifyRequest(email, loginCode, "d2", null), null,
                AuthDtos.TokenResponse.class).getBody();

        AuthDtos.SessionResponse[] sessions = rest.exchange("/auth/sessions",
                HttpMethod.GET, new HttpEntity<>(headers(first.accessToken())),
                AuthDtos.SessionResponse[].class).getBody();
        assertThat(sessions).hasSize(2);

        AuthDtos.SessionResponse device1 = null;
        for (AuthDtos.SessionResponse session : sessions) {
            if ("d1".equals(session.deviceId())) {
                device1 = session;
            }
        }
        assertThat(device1).isNotNull();

        assertThat(rest.exchange("/auth/sessions/" + device1.id(), HttpMethod.DELETE,
                new HttpEntity<>(headers(first.accessToken())),
                AuthDtos.MessageResponse.class).getStatusCode()).isEqualTo(HttpStatus.OK);

        assertThat(postStatus("/auth/token/refresh",
                new AuthDtos.RefreshRequest(first.refreshToken(), "d1")))
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(postStatus("/auth/token/refresh",
                new AuthDtos.RefreshRequest(second.refreshToken(), "d2")))
                .isEqualTo(HttpStatus.OK);
    }

    @Test
    void logoutAllRevokesEverySession() {
        String email = "logout-all@example.com";
        postStatus("/auth/register", new AuthDtos.RegisterRequest(email, "logoutall", null));
        String registerCode = capturedCode(email, EmailPurpose.REGISTER);
        AuthDtos.TokenResponse first = post("/auth/verify-email",
                new AuthDtos.VerifyEmailRequest(email, registerCode, "d1"), null,
                AuthDtos.TokenResponse.class).getBody();

        postStatus("/auth/otp/request", new AuthDtos.OtpRequest(email));
        String loginCode = capturedCode(email, EmailPurpose.LOGIN);
        AuthDtos.TokenResponse second = post("/auth/otp/verify",
                new AuthDtos.OtpVerifyRequest(email, loginCode, "d2", null), null,
                AuthDtos.TokenResponse.class).getBody();

        assertThat(rest.exchange("/auth/logout-all", HttpMethod.POST,
                new HttpEntity<>(headers(first.accessToken())),
                AuthDtos.MessageResponse.class).getStatusCode()).isEqualTo(HttpStatus.OK);

        assertThat(postStatus("/auth/token/refresh",
                new AuthDtos.RefreshRequest(first.refreshToken(), "d1")))
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(postStatus("/auth/token/refresh",
                new AuthDtos.RefreshRequest(second.refreshToken(), "d2")))
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void validationAndUnknownPathReturnStructuredErrors() {
        ResponseEntity<AuthDtos.ApiError> invalid = post("/auth/register",
                new AuthDtos.RegisterRequest("not-an-email", "u", null), null,
                AuthDtos.ApiError.class);
        assertThat(invalid.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(invalid.getBody().code()).isEqualTo("validation_error");

        ResponseEntity<AuthDtos.ApiError> missing = get("/.well-known/does-not-exist",
                null, AuthDtos.ApiError.class);
        assertThat(missing.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(missing.getBody().code()).isEqualTo("not_found");
    }

    @Test
    void corsAllowsConfiguredOriginAndRejectsForeign() {
        HttpHeaders allowed = new HttpHeaders();
        allowed.setOrigin("http://localhost:3000");
        allowed.setAccessControlRequestMethod(HttpMethod.GET);
        ResponseEntity<String> ok = rest.exchange("/auth/me", HttpMethod.OPTIONS,
                new HttpEntity<>(allowed), String.class);
        assertThat(ok.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(ok.getHeaders().getAccessControlAllowOrigin())
                .isEqualTo("http://localhost:3000");

        HttpHeaders foreign = new HttpHeaders();
        foreign.setOrigin("https://evil.example");
        foreign.setAccessControlRequestMethod(HttpMethod.GET);
        ResponseEntity<String> rejected = rest.exchange("/auth/me", HttpMethod.OPTIONS,
                new HttpEntity<>(foreign), String.class);
        assertThat(rejected.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void defensiveHeadersArePresentOnUnauthorizedResponse() {
        ResponseEntity<String> response = rest.exchange("/auth/me", HttpMethod.GET,
                new HttpEntity<>(new HttpHeaders()), String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(response.getHeaders().getFirst("X-Content-Type-Options")).isEqualTo("nosniff");
        assertThat(response.getHeaders().getFirst("X-Frame-Options")).isEqualTo("DENY");
        assertThat(response.getHeaders().getFirst("Cache-Control")).contains("no-store");
    }

    private String capturedCode(String email, EmailPurpose purpose) {
        ArgumentCaptor<String> captor = forClass(String.class);
        verify(mailService).sendOtp(eq(email), captor.capture(), eq(purpose));
        return captor.getValue();
    }

    private <T> ResponseEntity<T> post(String path, Object body, String token, Class<T> type) {
        return rest.exchange(path, HttpMethod.POST, new HttpEntity<>(body, headers(token)), type);
    }

    private HttpStatusCode postStatus(String path, Object body) {
        return rest.exchange(path, HttpMethod.POST, new HttpEntity<>(body, headers(null)), String.class)
                .getStatusCode();
    }

    private <T> ResponseEntity<T> get(String path, String token, Class<T> type) {
        return rest.exchange(path, HttpMethod.GET, new HttpEntity<>(headers(token)), type);
    }

    private HttpHeaders headers(String token) {
        HttpHeaders headers = new HttpHeaders();
        if (token != null) {
            headers.setBearerAuth(token);
        }
        return headers;
    }
}
