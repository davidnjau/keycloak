
package com.keycloak.common.exception;

import org.springframework.http.HttpStatus;

/**
 * Exception for resource not found (204).
 */
public class ContentNotFoundException extends ApplicationException {


    public ContentNotFoundException(String details) {
        super(details, HttpStatus.NO_CONTENT);
    }


    public ContentNotFoundException(String details, Throwable cause) {
        super(details, cause, HttpStatus.NO_CONTENT);
    }
}
