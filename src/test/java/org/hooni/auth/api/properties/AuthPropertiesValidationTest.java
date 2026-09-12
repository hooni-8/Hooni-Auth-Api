package org.hooni.auth.api.properties;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AuthPropertiesValidationTest {
    private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

    @Test
    void rejectsIncompleteJwtKeyPairAndValidity() {
        JwtProperties properties = new JwtProperties();
        properties.setPrivateKey("private-only");
        properties.setAccessTokenValidity(Duration.ZERO);

        assertThat(validator.validate(properties))
                .extracting(violation -> violation.getMessage())
                .contains(
                        "private-key and public-key must either both be configured or both be empty",
                        "access-token-validity and refresh-token-validity must be positive"
                );
    }

    @Test
    void rejectsInvalidOriginAndTrustedProxy() {
        SecurityProperties properties = new SecurityProperties();
        properties.setAllowedOrigin(List.of("*"));
        properties.setTrustedProxyAddresses(List.of("10.0.0.0/99"));

        assertThat(validator.validate(properties))
                .extracting(violation -> violation.getMessage())
                .contains(
                        "allowed-origin must contain only explicit http/https origins without paths",
                        "trusted-proxy-addresses must contain only valid IP addresses or CIDRs"
                );
    }

    @Test
    void rejectsInsecureSameSiteNoneCookie() {
        CookieProperties properties = new CookieProperties();
        properties.setSameSite("None");
        properties.setSecure(false);

        assertThat(validator.validate(properties))
                .extracting(violation -> violation.getMessage())
                .contains("SameSite=None cookies must be secure");
    }
}
