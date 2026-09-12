package org.hooni.auth.api.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.hooni.auth.api.properties.CookieProperties;
import org.hooni.auth.api.properties.SecurityProperties;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class OriginValidationFilter extends OncePerRequestFilter {
    private static final Set<String> SAFE_METHODS = Set.of(
            HttpMethod.GET.name(), HttpMethod.HEAD.name(), HttpMethod.OPTIONS.name()
    );

    private final SecurityProperties securityProperties;
    private final CookieProperties cookieProperties;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        String origin = request.getHeader("Origin");
        boolean hasAuthenticationCookie = request.getCookies() != null
                && Arrays.stream(request.getCookies()).anyMatch(cookie ->
                cookieProperties.getAccessTokenName().equals(cookie.getName())
                        || cookieProperties.getRefreshTokenName().equals(cookie.getName()));
        boolean invalidOrigin = origin != null
                && !securityProperties.getAllowedOrigin().contains(origin);
        boolean missingOriginForCookieRequest = origin == null && hasAuthenticationCookie;
        if (!SAFE_METHODS.contains(request.getMethod())
                && (invalidOrigin || missingOriginForCookieRequest)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        filterChain.doFilter(request, response);
    }
}
