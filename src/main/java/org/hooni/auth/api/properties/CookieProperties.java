package org.hooni.auth.api.properties;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Data
@Validated
@ConfigurationProperties(prefix = "application.cookie")
public class CookieProperties {

    private boolean secure;

    @NotBlank
    @Pattern(regexp = "(?i)Strict|Lax|None")
    private String sameSite = "Lax";

    @NotBlank
    @Pattern(regexp = "^[A-Za-z0-9_-]+$")
    private String accessTokenName = "accessToken";

    @NotBlank
    @Pattern(regexp = "^[A-Za-z0-9_-]+$")
    private String refreshTokenName = "refreshToken";

    @AssertTrue(message = "SameSite=None cookies must be secure")
    public boolean isNoneCookieSecure() {
        return !"None".equalsIgnoreCase(sameSite) || secure;
    }
}
