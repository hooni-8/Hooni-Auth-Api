package org.hooni.auth.api.security;

import jakarta.servlet.http.HttpServletRequest;
import org.hooni.auth.api.properties.SecurityProperties;
import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;

/** 신뢰하는 Gateway가 정제한 X-Client-IP만 Rate Limit 식별자로 사용한다. */
@Component
public class ClientIpResolver {
    private static final String CLIENT_IP_HEADER = "X-Client-IP";

    private final List<CidrMatcher> trustedProxies;

    public ClientIpResolver(SecurityProperties securityProperties) {
        this.trustedProxies = securityProperties.getTrustedProxyAddresses().stream()
                .map(CidrMatcher::new)
                .toList();
    }

    public String resolve(HttpServletRequest request) {
        String remoteAddress = request.getRemoteAddr();
        if (!isTrustedProxy(remoteAddress)) {
            return remoteAddress;
        }

        String forwardedAddress = request.getHeader(CLIENT_IP_HEADER);
        return isIpLiteral(forwardedAddress) ? forwardedAddress : remoteAddress;
    }

    private boolean isTrustedProxy(String address) {
        return isIpLiteral(address)
                && trustedProxies.stream().anyMatch(matcher -> matcher.matches(address));
    }

    private static boolean isIpLiteral(String address) {
        if (address == null
                || !(address.contains(".") || address.contains(":"))
                || !address.matches("[0-9a-fA-F:.]+")) {
            return false;
        }
        try {
            InetAddress.getByName(address);
            return true;
        } catch (UnknownHostException ignored) {
            return false;
        }
    }

    private static final class CidrMatcher {
        private final byte[] network;
        private final int prefixLength;

        private CidrMatcher(String value) {
            try {
                String[] parts = value.trim().split("/", 2);
                network = InetAddress.getByName(parts[0]).getAddress();
                prefixLength = parts.length == 1
                        ? network.length * 8
                        : Integer.parseInt(parts[1]);
            } catch (UnknownHostException | NumberFormatException exception) {
                throw new IllegalArgumentException("Invalid trusted proxy address: " + value, exception);
            }
        }

        private boolean matches(String address) {
            try {
                byte[] candidate = InetAddress.getByName(address).getAddress();
                if (candidate.length != network.length) {
                    return false;
                }
                int fullBytes = prefixLength / 8;
                int remainingBits = prefixLength % 8;
                for (int index = 0; index < fullBytes; index++) {
                    if (candidate[index] != network[index]) {
                        return false;
                    }
                }
                if (remainingBits == 0) {
                    return true;
                }
                int mask = 0xFF << (8 - remainingBits);
                return (candidate[fullBytes] & mask) == (network[fullBytes] & mask);
            } catch (UnknownHostException ignored) {
                return false;
            }
        }
    }
}
