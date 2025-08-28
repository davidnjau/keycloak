package com.keycloak.common.exception;

import com.keycloak.common.exception.ApplicationException;
import com.keycloak.common.exception.UnauthorizedException;
import com.keycloak.common.response.ResponseWrapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.ws.rs.NotAuthorizedException;

/**
 * Global exception handler for the application.
 * This class provides centralized exception handling across all @RequestMapping methods.
 */
@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Handles ApplicationException and returns an appropriate error response.
     *
     * @param ex The ApplicationException that was thrown
     * @return A ResponseEntity containing a ResponseWrapper with error details and the appropriate HTTP status
     */
    @ExceptionHandler(ApplicationException.class)
    public ResponseEntity<ResponseWrapper<Void>> handleApplicationException(ApplicationException ex) {
        return ResponseEntity
                .status(ex.getStatus())
                .body(ResponseWrapper.error(
                        ex.getMessage(),
                        ex.getStatus().value())
                );
    }

    /**
     * Handles generic exceptions and returns a 500 Internal Server Error response.
     *
     * @param ex The Exception that was thrown
     * @return A ResponseEntity containing a ResponseWrapper with a generic error message and 500 status code
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ResponseWrapper<Void>> handleGenericException(Exception ex) {
        return ResponseEntity
                .internalServerError()
                .body(ResponseWrapper
                        .error(
                                "An unexpected error occurred: " + ex.getMessage(),
                                500)
                );
    }

    /**
     * Handles UnauthorizedException and returns a 401 Unauthorized response.
     *
     * @param ex The UnauthorizedException that was thrown
     * @return A ResponseEntity with a 401 status and an error message
     */
    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<String> handleUnauthorized(UnauthorizedException ex) {
        log.error("Unauthorized error: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body("Invalid username or password");
    }

    /**
     * Handles NotAuthorizedException and returns a 401 Unauthorized response.
     *
     * @param ex The NotAuthorizedException that was thrown
     * @return A ResponseEntity containing a ResponseWrapper with an error message and 401 status code
     */
    @ExceptionHandler(NotAuthorizedException.class)
    public ResponseEntity<ResponseWrapper<Void>> handleUnauthorized(javax.ws.rs.NotAuthorizedException ex) {
        return ResponseEntity
                .status(ex.getResponse().getStatus())
                .body(ResponseWrapper
                        .error(
                                "Invalid username or password",
                                401
                        ));
    }
}
