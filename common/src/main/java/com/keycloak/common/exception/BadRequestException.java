package com.keycloak.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception for invalid requests (400).
 */
public class BadRequestException extends ApplicationException {

    public BadRequestException(String details) {
        super(details, HttpStatus.BAD_REQUEST);
    }

    public BadRequestException(String details, Throwable cause) {
        super(details, cause, HttpStatus.BAD_REQUEST);
    }
}
