package com.keycloak.common.exception;


import org.springframework.http.HttpStatus;

/**
 * Exception for unexpected server errors (500).
 */
public class InternalServerException extends ApplicationException {

    public InternalServerException(String details) {
        super(details, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    public InternalServerException(String details, Throwable cause) {
        super(details, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
