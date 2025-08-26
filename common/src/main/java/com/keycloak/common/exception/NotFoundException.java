package com.keycloak.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception for resource not found (404).
 */
public class NotFoundException extends ApplicationException {

    public NotFoundException(String details) {
        super(details, HttpStatus.NOT_FOUND);
    }

    public NotFoundException(String details, Throwable cause) {
        super(details, cause, HttpStatus.NOT_FOUND);
    }
}
