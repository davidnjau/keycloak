package com.keycloak.common.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception for resource not found (404).
 */
public class UserNotFoundException extends ApplicationException {

    public UserNotFoundException(String details) {
        super(details, HttpStatus.NOT_FOUND);
    }

    public UserNotFoundException(String details, Throwable cause) {
        super(details, cause, HttpStatus.NOT_FOUND);
    }
}
