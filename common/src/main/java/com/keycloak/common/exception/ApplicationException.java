package com.keycloak.common.exception;

import lombok.Getter;
import org.springframework.http.HttpStatus;

/**
 * Base class for all custom application exceptions.
 * Provides structured error handling with status codes and error codes.
 */
@Getter
public class ApplicationException extends RuntimeException {
    private final HttpStatus status;

    /**
     * Constructs a new ApplicationException with the specified details and HTTP status.
     *
     * @param details A string describing the exception details.
     * @param status The HTTP status code associated with this exception.
     */
    public ApplicationException(String details, HttpStatus status) {
        super(details);
        this.status = status;
    }

    /**
     * Constructs a new ApplicationException with the specified details, cause, and HTTP status.
     *
     * @param details A string describing the exception details.
     * @param cause The cause (which is saved for later retrieval by the Throwable.getCause() method).
     * @param status The HTTP status code associated with this exception.
     */
    public ApplicationException(String details, Throwable cause, HttpStatus status) {
        super(details, cause);
        this.status = status;
    }

}
