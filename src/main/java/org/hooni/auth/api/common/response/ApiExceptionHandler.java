package org.hooni.auth.api.common.response;

import lombok.extern.slf4j.Slf4j;
import org.hooni.auth.api.common.code.StatusCode;
import org.hooni.auth.api.common.exception.AuthException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@Slf4j
@RestControllerAdvice
public class ApiExceptionHandler {

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ApiResponse<Void>> handleAuthException(AuthException exception) {
        ResponseEntity.BodyBuilder response = ResponseEntity.status(exception.getHttpStatus());
        if (exception.getHttpStatus() == HttpStatus.TOO_MANY_REQUESTS) {
            response.header("Retry-After", "60");
        }
        return response.body(ApiResponse.error(exception.getStatusCode()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Void>> handleValidation() {
        return ResponseEntity.badRequest().body(ApiResponse.error(StatusCode.ERROR_VALID));
    }

    @ExceptionHandler(DuplicateKeyException.class)
    public ResponseEntity<ApiResponse<Void>> handleDuplicateUserId() {
        return ResponseEntity.status(HttpStatus.CONFLICT)
                .body(ApiResponse.error(StatusCode.DUPLICATE_USER_ID));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleUnexpectedException(Exception exception) {
        log.error("Unexpected auth-api error", exception);
        return ResponseEntity.internalServerError().body(ApiResponse.error(StatusCode.ERROR));
    }
}
