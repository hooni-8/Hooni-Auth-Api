package org.hooni.auth.api.properties;

import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

@Data
@Validated
@ConfigurationProperties(prefix = "application.security")
public class SecurityProperties {
    @NotEmpty
    private List<@NotBlank String> allowedOrigin = new ArrayList<>();

    /** X-Client-IP를 설정하는 신뢰 가능한 Gateway/Reverse Proxy IP 또는 CIDR이다. */
    @NotNull
    private List<@NotBlank String> trustedProxyAddresses = new ArrayList<>();

    @AssertTrue(message = "allowed-origin must contain only explicit http/https origins without paths")
    public boolean isAllowedOriginValid() {
        return allowedOrigin == null || allowedOrigin.stream().allMatch(this::isOrigin);
    }

    @AssertTrue(message = "trusted-proxy-addresses must contain only valid IP addresses or CIDRs")
    public boolean isTrustedProxyAddressesValid() {
        return trustedProxyAddresses == null
                || trustedProxyAddresses.stream().allMatch(this::isIpOrCidr);
    }

    private boolean isOrigin(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        try {
            URI uri = URI.create(value);
            return ("http".equalsIgnoreCase(uri.getScheme()) || "https".equalsIgnoreCase(uri.getScheme()))
                    && uri.getHost() != null
                    && (uri.getPath() == null || uri.getPath().isEmpty())
                    && uri.getQuery() == null
                    && uri.getFragment() == null;
        } catch (IllegalArgumentException ignored) {
            return false;
        }
    }

    private boolean isIpOrCidr(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        try {
            String[] parts = value.trim().split("/", 2);
            if (!isIpLiteral(parts[0])) {
                return false;
            }
            byte[] address = InetAddress.getByName(parts[0]).getAddress();
            if (parts.length == 1) {
                return true;
            }
            int prefix = Integer.parseInt(parts[1]);
            return prefix >= 0 && prefix <= address.length * 8;
        } catch (UnknownHostException | NumberFormatException ignored) {
            return false;
        }
    }

    private boolean isIpLiteral(String value) {
        return value != null
                && (value.contains(".") || value.contains(":"))
                && value.matches("[0-9a-fA-F:.]+");
    }
}
