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

    private ResponseWrapper(OffsetDateTime timestamp, int status, String details,
                            T data, boolean success, String errorCode) {
        this.timestamp = timestamp;
        this.status = status;
        this.details = details;
        this.data = data;
        this.success = success;
        this.errorCode = errorCode;
    }

    // ✅ Success factory methods
    public static <T> ResponseWrapper<T> success(T data, String details, int status) {
        return new ResponseWrapper<>(OffsetDateTime.now(), status, details, data, true, null);
    }

    public static <T> ResponseWrapper<T> success(T data, String details) {
        return success(data, details, 200);
    }

    public static <T> ResponseWrapper<T> success(T data) {
        return success(data, "The operation was successful", 200);
    }

    // ✅ Error factory methods
    public static ResponseWrapper<Void> error(String details, String errorCode, int status) {
        return new ResponseWrapper<>(OffsetDateTime.now(), status, details, null, false, errorCode);
    }

    public static ResponseWrapper<Void> error(String details, int status) {
        return error(details, null, status);
    }

}
