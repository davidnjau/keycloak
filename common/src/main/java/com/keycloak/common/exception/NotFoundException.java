
package com.keycloak.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception for resource not found (404).
 */
public class NotFoundException extends ApplicationException {

    /**
     * Constructs a new NotFoundException with the specified detail message.
     *
     * @param details A string containing the details of the exception.
     */
    public NotFoundException(String details) {
        super(details, HttpStatus.NOT_FOUND);
    }

    /**
     * Constructs a new NotFoundException with the specified detail message and cause.
     *
     * @param details A string containing the details of the exception.
     * @param cause The cause (which is saved for later retrieval by the Throwable.getCause() method).
     *              A null value is permitted, and indicates that the cause is nonexistent or unknown.
     */
    public NotFoundException(String details, Throwable cause) {
        super(details, cause, HttpStatus.NOT_FOUND);
    }
}
