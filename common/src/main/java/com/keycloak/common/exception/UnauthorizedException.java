package com.keycloak.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception for unauthorized access (401).
 */
public class UnauthorizedException extends ApplicationException {

    public UnauthorizedException(String details) {
        super(details, HttpStatus.UNAUTHORIZED);
    }

    public UnauthorizedException(String details, Throwable cause) {
        super(details, cause, HttpStatus.UNAUTHORIZED);
    }
}
