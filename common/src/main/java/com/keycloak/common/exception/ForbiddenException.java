package com.keycloak.common.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception for forbidden access (403).
 */
public class ForbiddenException extends ApplicationException {


    public ForbiddenException(String details) {
        super(details, HttpStatus.FORBIDDEN);
    }

    public ForbiddenException(String details, Throwable cause) {
        super(details, cause, HttpStatus.FORBIDDEN);
    }
}
