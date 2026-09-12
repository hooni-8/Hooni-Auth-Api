package org.hooni.auth.api.common.response;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/** 표준 프로토콜처럼 응답 JSON 구조를 그대로 유지해야 하는 API에 사용한다. */
@Target({ElementType.TYPE, ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface RawResponse {
}
