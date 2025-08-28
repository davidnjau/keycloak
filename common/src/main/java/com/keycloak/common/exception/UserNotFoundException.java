
package com.keycloak.common.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception for resource not found (404).
 * This exception is thrown when a user resource is not found in the system.
 */
public class UserNotFoundException extends ApplicationException {

    /**
     * Constructs a new UserNotFoundException with the specified detail message.
     *
     * @param details A description of the exception.
     */
    public UserNotFoundException(String details) {
        super(details, HttpStatus.NOT_FOUND);
    }

    /**
     * Constructs a new UserNotFoundException with the specified detail message and cause.
     *
     * @param details A description of the exception.
     * @param cause The cause of the exception. (A null value is permitted, and indicates that the cause is nonexistent or unknown.)
     */
    public UserNotFoundException(String details, Throwable cause) {
        super(details, cause, HttpStatus.NOT_FOUND);
    }
}
