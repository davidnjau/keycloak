
package com.keycloak.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception for invalid requests (400).
 * This exception is thrown when a client sends an invalid request to the server.
 */
public class BadRequestException extends ApplicationException {

    /**
     * Constructs a new BadRequestException with the specified detail message.
     *
     * @param details A string containing the details of the exception.
     */
    public BadRequestException(String details) {
        super(details, HttpStatus.BAD_REQUEST);
    }

    /**
     * Constructs a new BadRequestException with the specified detail message and cause.
     *
     * @param details A string containing the details of the exception.
     * @param cause   The cause of the exception. (A null value is permitted, and indicates that the cause is nonexistent or unknown.)
     */
    public BadRequestException(String details, Throwable cause) {
        super(details, cause, HttpStatus.BAD_REQUEST);
    }
}
