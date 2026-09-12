package org.hooni.auth.api.properties;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;

/** JWT 발급과 검증에 사용하는 issuer, audience, RSA 키와 유효기간 설정이다. */
@Data
@Validated
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {

    @NotBlank
    private String issuer = "hooni-template-auth";

    @NotBlank
    private String audience = "hooni-template-api";

    @NotBlank
    private String keyId = "hooni-template-rsa";

    @NotBlank
    @Pattern(regexp = "RS256")
    private String algorithm = "RS256";

    /** Base64 PKCS#8 개인키. 두 키가 비어 있으면 로컬 개발용 키 쌍을 실행 시 생성한다. */
    private String privateKey;

    /** Base64 X.509 공개키. */
    private String publicKey;

    @NotNull
    private Duration accessTokenValidity = Duration.ofMinutes(15);

    @NotNull
    private Duration refreshTokenValidity = Duration.ofDays(7);

    @AssertTrue(message = "access-token-validity and refresh-token-validity must be positive")
    public boolean isTokenValidityPositive() {
        return (accessTokenValidity == null || !accessTokenValidity.isZero() && !accessTokenValidity.isNegative())
                && (refreshTokenValidity == null || !refreshTokenValidity.isZero() && !refreshTokenValidity.isNegative());
    }

    @AssertTrue(message = "private-key and public-key must either both be configured or both be empty")
    public boolean isKeyPairConfigurationComplete() {
        return isBlank(privateKey) == isBlank(publicKey);
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
