package org.hooni.auth.api.controller.v1.auth;

import lombok.RequiredArgsConstructor;
import org.hooni.auth.api.common.response.RawResponse;
import org.hooni.auth.api.service.auth.JwkService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/** Gateway와 Resource API가 JWT 서명을 검증할 수 있도록 RSA 공개키만 제공한다. */
@RestController
@RequiredArgsConstructor
@RawResponse
public class JwkController {

    private final JwkService jwkService;

    /** Service가 생성한 표준 JWKS 공개키 문서를 응답 형식 변경 없이 반환한다. */
    @GetMapping("/oauth2/jwks")
    public Map<String, Object> keys() {
        return jwkService.getJwkSet();
    }
}
