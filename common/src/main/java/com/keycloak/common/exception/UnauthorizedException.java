
package com.keycloak.common.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Exception for unauthorized access (401).
 * This exception is thrown when a user attempts to access a resource without proper authentication.
 */
public class UnauthorizedException extends ApplicationException {

    /**
     * Constructs a new UnauthorizedException with the specified detail message.
     *
     * @param details A string containing the details of the unauthorized access attempt.
     */
    public UnauthorizedException(String details) {
        super(details, HttpStatus.UNAUTHORIZED);
    }

    /**
     * Constructs a new UnauthorizedException with the specified detail message and cause.
     *
     * @param details A string containing the details of the unauthorized access attempt.
     * @param cause   The cause (which is saved for later retrieval by the Throwable.getCause() method).
     *                A null value is permitted, and indicates that the cause is nonexistent or unknown.
     */
    public UnauthorizedException(String details, Throwable cause) {
        super(details, cause, HttpStatus.UNAUTHORIZED);
    }
}
