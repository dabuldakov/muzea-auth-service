package com.muzea.auth.error;

import org.springframework.http.HttpStatus;

/** Ошибка аутентификации/валидации с HTTP-статусом. */
public class AuthException extends RuntimeException {

    private final HttpStatus status;
    private final String code;

    public AuthException(HttpStatus status, String code, String message) {
        super(message);
        this.status = status;
        this.code = code;
    }

    public static AuthException badRequest(String code, String message) {
        return new AuthException(HttpStatus.BAD_REQUEST, code, message);
    }

    public static AuthException unauthorized(String code, String message) {
        return new AuthException(HttpStatus.UNAUTHORIZED, code, message);
    }

    public static AuthException conflict(String code, String message) {
        return new AuthException(HttpStatus.CONFLICT, code, message);
    }

    public static AuthException tooManyRequests(String code, String message) {
        return new AuthException(HttpStatus.TOO_MANY_REQUESTS, code, message);
    }

    public HttpStatus status() {
        return status;
    }

    public String code() {
        return code;
    }
}
