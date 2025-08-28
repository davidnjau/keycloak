
/**
 * A generic wrapper class for API responses.
 * This class encapsulates common response attributes and provides factory methods for creating success and error responses.
 *
 * @param <T> The type of data contained in the response
 */
package com.keycloak.common.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import lombok.Getter;
import lombok.ToString;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;

@Getter
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonPropertyOrder({"timestamp", "status", "success", "details", "data", "errorCode"})
public class ResponseWrapper<T> implements Serializable {

    // ✅ Getters
    private final OffsetDateTime timestamp;
    private final int status;
    private final String details;
    private final T data;
    private final boolean success;
    private final String errorCode;

    /**
     * Private constructor for creating ResponseWrapper instances.
     *
     * @param timestamp The timestamp of the response
     * @param status    The HTTP status code of the response
     * @param details   Additional details or message about the response
     * @param data      The payload or data of the response
     * @param success   Indicates whether the operation was successful
     * @param errorCode The error code, if applicable
     */
    private ResponseWrapper(OffsetDateTime timestamp, int status, String details,
                            T data, boolean success, String errorCode) {
        this.timestamp = timestamp;
        this.status = status;
        this.details = details;
        this.data = data;
        this.success = success;
        this.errorCode = errorCode;
    }

    /**
     * Creates a success response with custom data, details, and status.
     *
     * @param <T>     The type of data
     * @param data    The payload or data of the response
     * @param details Additional details or message about the response
     * @param status  The HTTP status code of the response
     * @return A new ResponseWrapper instance representing a successful operation
     */
    public static <T> ResponseWrapper<T> success(T data, String details, int status) {
        return new ResponseWrapper<>(OffsetDateTime.now(), status, details, data, true, null);
    }

    /**
     * Creates a success response with custom data and details, using the default HTTP status code 200.
     *
     * @param <T>     The type of data
     * @param data    The payload or data of the response
     * @param details Additional details or message about the response
     * @return A new ResponseWrapper instance representing a successful operation
     */
    public static <T> ResponseWrapper<T> success(T data, String details) {
        return success(data, details, 200);
    }

    /**
     * Creates a success response with custom data, using default details and HTTP status code 200.
     *
     * @param <T>  The type of data
     * @param data The payload or data of the response
     * @return A new ResponseWrapper instance representing a successful operation
     */
    public static <T> ResponseWrapper<T> success(T data) {
        return success(data, "The operation was successful", 200);
    }

    /**
     * Creates an error response with custom details, error code, and status.
     *
     * @param details   Additional details or message about the error
     * @param errorCode The error code associated with the error
     * @param status    The HTTP status code of the error response
     * @return A new ResponseWrapper instance representing an error
     */
    public static ResponseWrapper<Void> error(String details, String errorCode, int status) {
        return new ResponseWrapper<>(OffsetDateTime.now(), status, details, null, false, errorCode);
    }

    /**
     * Creates an error response with custom details and status, without an error code.
     *
     * @param details Additional details or message about the error
     * @param status  The HTTP status code of the error response
     * @return A new ResponseWrapper instance representing an error
     */
    public static ResponseWrapper<Void> error(String details, int status) {
        return error(details, null, status);
    }

}
