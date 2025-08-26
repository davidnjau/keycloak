package com.keycloak.common.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception for conflict errors (409).
 */
public class ConflictException extends ApplicationException {


    public ConflictException(String details) {
        super(details, HttpStatus.CONFLICT);
    }

    public ConflictException(String details, Throwable cause) {
        super(details, cause, HttpStatus.CONFLICT);
    }
}

