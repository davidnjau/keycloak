
package com.keycloak.common.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception for forbidden access (403).
 */
public class ForbiddenException extends ApplicationException {

    /**
     * Constructs a new ForbiddenException with the specified detail message.
     *
     * @param details A string containing the details of the forbidden access.
     */
    public ForbiddenException(String details) {
        super(details, HttpStatus.FORBIDDEN);
    }

    /**
     * Constructs a new ForbiddenException with the specified detail message and cause.
     *
     * @param details A string containing the details of the forbidden access.
     * @param cause The cause (which is saved for later retrieval by the Throwable.getCause() method).
     *              A null value is permitted, and indicates that the cause is nonexistent or unknown.
     */
    public ForbiddenException(String details, Throwable cause) {
        super(details, cause, HttpStatus.FORBIDDEN);
    }
}
