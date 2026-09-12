package org.hooni.auth.api.common.response;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.hooni.auth.api.common.code.StatusCode;

@Getter
@AllArgsConstructor
public class ApiResponse<T> {
    private final String code;
    private final String message;
    private final T data;

    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(StatusCode.SUCCESS.getCode(), StatusCode.SUCCESS.getMessage(), data);
    }

    public static ApiResponse<Void> success() {
        return success(null);
    }

    public static ApiResponse<Void> error(StatusCode statusCode) {
        return new ApiResponse<>(statusCode.getCode(), statusCode.getMessage(), null);
    }
}
