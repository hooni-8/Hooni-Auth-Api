package org.hooni.auth.api.common.code;

import lombok.Getter;

@Getter
public enum StatusCode {
    SUCCESS("0000", "SUCCESS"),
    ERROR_VALID("0001", "ERROR_VALID"),
    FORBIDDEN("0002", "FORBIDDEN"),
    LOGIN_FAIL("1001", "LOGIN_FAIL"),
    DUPLICATE_USER_ID("1002", "DUPLICATE_USER_ID"),
    UNAUTHORIZED("1003", "UNAUTHORIZED"),
    TOO_MANY_REQUESTS("1004", "TOO_MANY_REQUESTS"),
    ERROR("9999", "ERROR");

    private final String code;
    private final String message;

    StatusCode(String code, String message) {
        this.code = code;
        this.message = message;
    }
}
