package com.muzea.auth.web;

import com.muzea.auth.error.AuthException;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ApiExceptionHandlerTest {

    private final ApiExceptionHandler handler = new ApiExceptionHandler();

    @Test
    void authExceptionKeepsStatusAndCode() {
        var response = handler.handleAuth(
                AuthException.tooManyRequests("ip_rate_limit", "too many"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().code()).isEqualTo("ip_rate_limit");
    }

    @Test
    void missingResourceIsNotFound() {
        var response = handler.handleNotFound(mock(NoResourceFoundException.class));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
        assertThat(response.getBody().code()).isEqualTo("not_found");
    }

    @Test
    void validationReturnsFirstFieldError() {
        var ex = mock(MethodArgumentNotValidException.class);
        var binding = mock(BindingResult.class);
        when(ex.getBindingResult()).thenReturn(binding);
        when(binding.getFieldErrors())
                .thenReturn(List.of(new FieldError("request", "email", "must not be blank")));

        var response = handler.handleValidation(ex);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody().code()).isEqualTo("validation_error");
        assertThat(response.getBody().message()).isEqualTo("must not be blank");
    }

    @Test
    void accessDeniedIsForbidden() {
        var response = handler.handleAccessDenied(new AccessDeniedException("no"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getBody().code()).isEqualTo("access_denied");
    }

    @Test
    void unexpectedErrorDoesNotLeakDetails() {
        var response = handler.handleUnexpected(new RuntimeException("secret detail"));

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR);
        assertThat(response.getBody().code()).isEqualTo("internal_error");
        assertThat(response.getBody().message()).doesNotContain("secret detail");
    }
}
