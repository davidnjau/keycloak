package com.keycloak.common.exception;

import com.keycloak.common.response.ResponseWrapper;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.util.logging.Logger;

@Slf4j
@ControllerAdvice(basePackages = "com.keycloak")
public class GlobalExceptionHandler {

    @ExceptionHandler(BadRequestException.class)
    public ResponseEntity<ResponseWrapper<Void>> handleBadRequest(BadRequestException ex) {
        log.warn("Bad request: {}", ex.getMessage());
        ResponseWrapper<Void> body = ResponseWrapper.error(ex.getMessage(), ex.getErrorCode(), HttpStatus.BAD_REQUEST.value());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<ResponseWrapper<Void>> handleUnauthorized(UnauthorizedException ex) {
        log.warn("Unauthorized: {}", ex.getMessage());
        ResponseWrapper<Void> body = ResponseWrapper.error(ex.getMessage(), ex.getErrorCode(), HttpStatus.UNAUTHORIZED.value());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }

    @ExceptionHandler(NotFoundException.class)
    public ResponseEntity<ResponseWrapper<Void>> handleNotFound(NotFoundException ex) {
        log.warn("Not found: {}", ex.getMessage());
        ResponseWrapper<Void> body = ResponseWrapper.error(ex.getMessage(), ex.getErrorCode(), HttpStatus.NOT_FOUND.value());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(body);
    }

    @ExceptionHandler(ApplicationException.class)
    public ResponseEntity<ResponseWrapper<Void>> handleAppException(ApplicationException ex) {
        log.warn("Application exception: {}", ex.getMessage());
        ResponseWrapper<Void> body = ResponseWrapper.error(ex.getMessage(), ex.getErrorCode(), HttpStatus.BAD_REQUEST.value());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ResponseWrapper<Void>> handleGeneric(Exception ex) {
        // Keep stack trace in logs, but return a sanitized message.
        log.error("Unhandled exception", ex);
        ResponseWrapper<Void> body = ResponseWrapper.error("Internal server error", HttpStatus.INTERNAL_SERVER_ERROR.value());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }
}
