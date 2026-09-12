package org.hooni.auth.api.common.exception;

import lombok.Getter;
import org.hooni.auth.api.common.code.StatusCode;
import org.springframework.http.HttpStatus;

@Getter
public class AuthException extends RuntimeException {
    private final HttpStatus httpStatus;
    private final StatusCode statusCode;

    public AuthException(HttpStatus httpStatus, StatusCode statusCode) {
        super(statusCode.getMessage());
        this.httpStatus = httpStatus;
        this.statusCode = statusCode;
    }
}
