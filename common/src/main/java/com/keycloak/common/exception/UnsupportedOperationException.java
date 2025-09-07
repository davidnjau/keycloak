
package com.keycloak.common.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception for invalid requests (400).
 * This exception is thrown when a client sends an invalid request to the server.
 */
public class UnsupportedOperationException extends ApplicationException {

    /**
     * Constructs a new BadRequestException with the specified detail message.
     *
     * @param details A string containing the details of the exception.
     */
    public UnsupportedOperationException(String details) {
        super(details, HttpStatus.NOT_IMPLEMENTED);
    }

    /**
     * Constructs a new BadRequestException with the specified detail message and cause.
     *
     * @param details A string containing the details of the exception.
     * @param cause   The cause of the exception. (A null value is permitted, and indicates that the cause is nonexistent or unknown.)
     */
    public UnsupportedOperationException(String details, Throwable cause) {
        super(details, cause, HttpStatus.NOT_IMPLEMENTED);
    }
}
