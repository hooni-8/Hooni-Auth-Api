package org.hooni.auth.api.security;

import org.hooni.auth.api.properties.SecurityProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ClientIpResolverTest {

    @Test
    void ignoresSpoofedHeaderFromUntrustedClient() {
        ClientIpResolver resolver = resolver(List.of());
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("203.0.113.10");
        request.addHeader("X-Client-IP", "198.51.100.20");

        assertThat(resolver.resolve(request)).isEqualTo("203.0.113.10");
    }

    @Test
    void usesSanitizedHeaderFromTrustedProxyCidr() {
        ClientIpResolver resolver = resolver(List.of("10.244.0.0/16"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.244.81.137");
        request.addHeader("X-Client-IP", "203.0.113.10");

        assertThat(resolver.resolve(request)).isEqualTo("203.0.113.10");
    }

    @Test
    void ignoresMalformedHeaderEvenFromTrustedProxy() {
        ClientIpResolver resolver = resolver(List.of("10.244.0.0/16"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr("10.244.81.137");
        request.addHeader("X-Client-IP", "client.example.com");

        assertThat(resolver.resolve(request)).isEqualTo("10.244.81.137");
    }

    private ClientIpResolver resolver(List<String> trustedAddresses) {
        SecurityProperties properties = new SecurityProperties();
        properties.setTrustedProxyAddresses(trustedAddresses);
        return new ClientIpResolver(properties);
    }
}
