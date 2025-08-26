package com.keycloak.common.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * Base class for all custom application exceptions.
 * Provides structured error handling with status codes and error codes.
 */
@Getter
public class ApplicationException extends RuntimeException {
    private final HttpStatus status;

    public ApplicationException(String details, HttpStatus status) {
        super(details);
        this.status = status;
    }

    public ApplicationException(String details, Throwable cause, HttpStatus status) {
        super(details, cause);
        this.status = status;
    }

}

