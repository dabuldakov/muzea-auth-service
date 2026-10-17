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
