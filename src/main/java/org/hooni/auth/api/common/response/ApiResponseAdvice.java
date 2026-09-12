package org.hooni.auth.api.common.response;

import org.springframework.core.MethodParameter;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.ByteArrayHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.ResourceHttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;
import org.springframework.web.servlet.mvc.method.annotation.StreamingResponseBody;

/** Controller의 일반 반환값을 성공 ApiResponse로 자동 변환한다. */
@RestControllerAdvice(basePackages = "org.hooni.auth.api.controller")
public class ApiResponseAdvice implements ResponseBodyAdvice<Object> {

    @Override
    public boolean supports(
            MethodParameter returnType,
            Class<? extends HttpMessageConverter<?>> converterType
    ) {
        Class<?> returnClass = returnType.getParameterType();

        return !returnType.hasMethodAnnotation(RawResponse.class)
                && !returnType.getContainingClass().isAnnotationPresent(RawResponse.class)
                && !ApiResponse.class.isAssignableFrom(returnClass)
                && !Resource.class.isAssignableFrom(returnClass)
                && !StreamingResponseBody.class.isAssignableFrom(returnClass)
                && !ResourceHttpMessageConverter.class.isAssignableFrom(converterType)
                && !ByteArrayHttpMessageConverter.class.isAssignableFrom(converterType)
                && !StringHttpMessageConverter.class.isAssignableFrom(converterType)
                && !isResourceResponse(returnType);
    }

    @Override
    public Object beforeBodyWrite(
            Object body,
            MethodParameter returnType,
            MediaType selectedContentType,
            Class<? extends HttpMessageConverter<?>> selectedConverterType,
            ServerHttpRequest request,
            ServerHttpResponse response
    ) {
        if (body instanceof ApiResponse<?>) {
            return body;
        }
        return ApiResponse.success(body);
    }

    private boolean isResourceResponse(MethodParameter returnType) {
        if (!ResponseEntity.class.isAssignableFrom(returnType.getParameterType())) {
            return false;
        }
        return returnType.getGenericParameterType().getTypeName().contains(Resource.class.getName());
    }
}
