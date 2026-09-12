package org.hooni.auth.api.service.auth;

import org.hooni.auth.api.common.code.StatusCode;
import org.hooni.auth.api.common.exception.AuthException;
import org.hooni.auth.api.model.auth.AuthTokens;
import org.hooni.auth.api.model.auth.LoginStatus;
import org.hooni.auth.api.model.auth.request.LoginRequest;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthApplicationServiceTest {

    @Test
    void loginAppliesIpAndUserLimitsThenResetsUserFailuresOnSuccess() {
        AuthService authService = mock(AuthService.class);
        AuthRateLimitService rateLimitService = mock(AuthRateLimitService.class);
        AuthApplicationService service = new AuthApplicationService(authService, rateLimitService);
        LoginRequest request = new LoginRequest();
        request.setUserId("User01");
        request.setPassword("password1");
        AuthTokens tokens = new AuthTokens("access", "refresh");
        when(authService.login(request)).thenReturn(tokens);

        AuthTokens result = service.login(request, "203.0.113.10");

        assertThat(result).isSameAs(tokens);
        var ordered = inOrder(rateLimitService, authService);
        ordered.verify(rateLimitService).check("login-ip", "203.0.113.10", 30, Duration.ofMinutes(1));
        ordered.verify(rateLimitService).check("login-user", "user01", 10, Duration.ofMinutes(5));
        ordered.verify(authService).login(request);
        ordered.verify(rateLimitService).reset("login-user", "user01");
    }

    @Test
    void sessionReturnsRefreshCapabilityWhenAccessTokenIsInvalid() {
        AuthService authService = mock(AuthService.class);
        AuthApplicationService service = new AuthApplicationService(
                authService,
                mock(AuthRateLimitService.class)
        );
        when(authService.session("invalid-access")).thenThrow(
                new AuthException(HttpStatus.UNAUTHORIZED, StatusCode.UNAUTHORIZED)
        );
        when(authService.isRefreshable("valid-refresh")).thenReturn(true);

        LoginStatus status = service.session("invalid-access", "valid-refresh");

        assertThat(status.isStatus()).isFalse();
        assertThat(status.isRefreshable()).isTrue();
        verify(authService).isRefreshable("valid-refresh");
    }

    @Test
    void refreshRejectsMissingTokenAfterApplyingIpLimit() {
        AuthRateLimitService rateLimitService = mock(AuthRateLimitService.class);
        AuthApplicationService service = new AuthApplicationService(
                mock(AuthService.class),
                rateLimitService
        );

        assertThatThrownBy(() -> service.refresh(null, "203.0.113.10"))
                .isInstanceOf(AuthException.class);
        verify(rateLimitService).check("refresh", "203.0.113.10", 60, Duration.ofMinutes(1));
    }
}
