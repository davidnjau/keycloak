
package com.keycloak.common.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception for conflict errors (409).
 */
public class ConflictException extends ApplicationException {

    /**
     * Constructs a new ConflictException with the specified detail message.
     *
     * @param details A string containing the details of the conflict error.
     */
    public ConflictException(String details) {
        super(details, HttpStatus.CONFLICT);
    }

    /**
     * Constructs a new ConflictException with the specified detail message and cause.
     *
     * @param details A string containing the details of the conflict error.
     * @param cause The cause (which is saved for later retrieval by the Throwable.getCause() method).
     *              A null value is permitted, and indicates that the cause is nonexistent or unknown.
     */
    public ConflictException(String details, Throwable cause) {
        super(details, cause, HttpStatus.CONFLICT);
    }
}
