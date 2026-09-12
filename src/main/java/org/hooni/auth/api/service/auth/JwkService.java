package org.hooni.auth.api.service.auth;

import lombok.RequiredArgsConstructor;
import org.hooni.auth.api.properties.JwtProperties;
import org.hooni.auth.api.security.RsaKeyProvider;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;

/** Gateway와 Resource API에 공개할 RSA 공개키를 표준 JWKS 형식으로 생성한다. */
@Service
@RequiredArgsConstructor
public class JwkService {

    private final RsaKeyProvider keyProvider;
    private final JwtProperties jwtProperties;

    /** 현재 공개키의 알고리즘, 키 ID, modulus와 exponent를 JWKS 문서로 반환한다. */
    public Map<String, Object> getJwkSet() {
        return Map.of("keys", List.of(Map.of(
                "kty", "RSA",
                "use", "sig",
                "alg", jwtProperties.getAlgorithm(),
                "kid", keyProvider.getKeyId(),
                "n", encodeUnsigned(keyProvider.getPublicKey().getModulus()),
                "e", encodeUnsigned(keyProvider.getPublicKey().getPublicExponent())
        )));
    }

    /** RSA 정수를 부호 없는 Base64 URL 형식으로 변환한다. */
    private String encodeUnsigned(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
