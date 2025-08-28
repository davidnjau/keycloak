
package com.keycloak.common.exception;


import org.springframework.http.HttpStatus;

/**
 * Exception for unexpected server errors (500).
 */
public class InternalServerException extends ApplicationException {

    /**
     * Constructs a new InternalServerException with the specified detail message.
     *
     * @param details A string containing the details of the exception.
     */
    public InternalServerException(String details) {
        super(details, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    /**
     * Constructs a new InternalServerException with the specified detail message and cause.
     *
     * @param details A string containing the details of the exception.
     * @param cause   The cause (which is saved for later retrieval by the Throwable.getCause() method).
     *                A null value is permitted, and indicates that the cause is nonexistent or unknown.
     */
    public InternalServerException(String details, Throwable cause) {
        super(details, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}
