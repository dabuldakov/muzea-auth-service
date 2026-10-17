package com.muzea.auth.web;

import com.muzea.auth.error.AuthException;
import com.muzea.auth.web.dto.AuthDtos;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.resource.NoResourceFoundException;

@Slf4j
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<AuthDtos.ApiError> handleAuth(AuthException ex) {
        return ResponseEntity.status(ex.status())
                .body(new AuthDtos.ApiError(ex.code(), ex.getMessage()));
    }

    /** Неизвестный путь (в т.ч. сканеры вроде /.well-known/security.txt) → 404, не 500. */
    @ExceptionHandler(NoResourceFoundException.class)
    public ResponseEntity<AuthDtos.ApiError> handleNotFound(NoResourceFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(new AuthDtos.ApiError("not_found", "Not found"));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<AuthDtos.ApiError> handleValidation(MethodArgumentNotValidException ex) {
        String message = ex.getBindingResult().getFieldErrors().stream()
                .findFirst()
                .map(FieldError::getDefaultMessage)
                .orElse("Validation failed");
        return ResponseEntity.badRequest()
                .body(new AuthDtos.ApiError("validation_error", message));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<AuthDtos.ApiError> handleAccessDenied(AccessDeniedException ex) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new AuthDtos.ApiError("access_denied", "Access denied"));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<AuthDtos.ApiError> handleUnexpected(Exception ex) {
        log.error("Unexpected error", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(new AuthDtos.ApiError("internal_error", "Internal server error"));
    }
}
