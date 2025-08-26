package com.keycloak.common.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.ToString;

import java.time.LocalDateTime;
import java.time.OffsetDateTime;

@Getter
@ToString
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ResponseWrapper<T> {
    private final OffsetDateTime timestamp;
    private final int status;
    private final String message;
    private final T data;
    private final boolean success;
    private final String errorCode;

    private ResponseWrapper(OffsetDateTime timestamp, int status, String message, T data, boolean success, String errorCode) {
        this.timestamp = timestamp;
        this.status = status;
        this.message = message;
        this.data = data;
        this.success = success;
        this.errorCode = errorCode;
    }

    public static <T> ResponseWrapper<T> success(T data, String message, int status) {
        return new ResponseWrapper<>(OffsetDateTime.now(), status, message, data, true, null);
    }

    public static <T> ResponseWrapper<T> success(T data, String message) {
        return success(data, message, 200);
    }

    public static ResponseWrapper<Void> error(String message, String errorCode, int status) {
        return new ResponseWrapper<>(OffsetDateTime.now(), status, message, null, false, errorCode);
    }

    public static ResponseWrapper<Void> error(String message, int status) {
        return error(message, null, status);
    }
}
