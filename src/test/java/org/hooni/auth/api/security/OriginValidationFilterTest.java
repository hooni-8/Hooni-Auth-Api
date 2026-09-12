package org.hooni.auth.api.security;

import jakarta.servlet.http.Cookie;
import org.hooni.auth.api.properties.CookieProperties;
import org.hooni.auth.api.properties.SecurityProperties;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class OriginValidationFilterTest {

    @Test
    void rejectsUnsafeCookieRequestWithoutOrigin() throws Exception {
        OriginValidationFilter filter = filter();
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/auth/refresh");
        request.setCookies(new Cookie("refreshToken", "token"));
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void rejectsExplicitlyUntrustedOriginWithoutCookies() throws Exception {
        OriginValidationFilter filter = filter();
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/auth/login");
        request.addHeader("Origin", "https://attacker.example");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(403);
    }

    @Test
    void permitsServerRequestWithoutOriginOrCookie() throws Exception {
        OriginValidationFilter filter = filter();
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/auth/login");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        assertThat(response.getStatus()).isEqualTo(200);
    }

    private OriginValidationFilter filter() {
        SecurityProperties security = new SecurityProperties();
        security.setAllowedOrigin(List.of("http://localhost:3000"));
        return new OriginValidationFilter(security, new CookieProperties());
    }
}
