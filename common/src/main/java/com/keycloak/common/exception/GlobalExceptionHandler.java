package com.keycloak.common.exception;

import com.keycloak.common.response.ResponseWrapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.ws.rs.NotAuthorizedException;
import java.util.logging.Logger;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ApplicationException.class)
    public ResponseEntity<ResponseWrapper<Void>> handleApplicationException(ApplicationException ex) {
        return ResponseEntity
                .status(ex.getStatus())
                .body(ResponseWrapper.error(
                        ex.getMessage(),
                        ex.getStatus().value())
                );
    }

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

    @ExceptionHandler(UnauthorizedException.class)
    public ResponseEntity<String> handleUnauthorized(UnauthorizedException ex) {
        log.error("Unauthorized error: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body("Invalid username or password");
    }

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
