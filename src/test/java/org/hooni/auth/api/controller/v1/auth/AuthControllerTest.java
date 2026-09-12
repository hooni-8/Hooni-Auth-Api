package org.hooni.auth.api.controller.v1.auth;

import jakarta.servlet.http.Cookie;
import org.hooni.auth.api.common.response.ApiResponseAdvice;
import org.hooni.auth.api.model.auth.AuthTokens;
import org.hooni.auth.api.model.auth.LoginStatus;
import org.hooni.auth.api.model.auth.request.LoginRequest;
import org.hooni.auth.api.properties.CookieProperties;
import org.hooni.auth.api.properties.JwtProperties;
import org.hooni.auth.api.security.ClientIpResolver;
import org.hooni.auth.api.service.auth.AuthApplicationService;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.nullValue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class AuthControllerTest {

    @Test
    void responseAdviceWrapsDataAndEmptyControllerResponses() throws Exception {
        AuthApplicationService applicationService = mock(AuthApplicationService.class);
        when(applicationService.session(null, null)).thenReturn(loggedOut(false));
        AuthController controller = controller(applicationService, mock(ClientIpResolver.class));
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(controller)
                .setControllerAdvice(new ApiResponseAdvice())
                .build();

        mockMvc.perform(post("/auth/session"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.code").value("0000"))
                .andExpect(jsonPath("$.message").value("SUCCESS"))
                .andExpect(jsonPath("$.data.status").value(false))
                .andExpect(jsonPath("$.data.refreshable").value(false));

        mockMvc.perform(post("/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {
                                  "userId": "user01",
                                  "userPassword": "password1",
                                  "userName": "사용자"
                                }
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.code").value("0000"))
                .andExpect(jsonPath("$.message").value("SUCCESS"))
                .andExpect(jsonPath("$.data").value(nullValue()));
    }

    @Test
    void loginReturnsAccessAndRefreshCookiesForGatewayRelay() {
        AuthApplicationService applicationService = mock(AuthApplicationService.class);
        ClientIpResolver clientIpResolver = mock(ClientIpResolver.class);
        AuthController controller = controller(applicationService, clientIpResolver);
        LoginRequest login = new LoginRequest();
        login.setUserId("user01");
        login.setPassword("password1");
        MockHttpServletRequest request = new MockHttpServletRequest();
        when(clientIpResolver.resolve(request)).thenReturn("203.0.113.10");
        when(applicationService.login(any(LoginRequest.class), eq("203.0.113.10")))
                .thenReturn(new AuthTokens("access-value", "refresh-value"));

        var response = controller.login(login, request);

        assertThat(response.getHeaders().get(HttpHeaders.SET_COOKIE))
                .hasSize(2)
                .anyMatch(value -> value.contains("accessToken=access-value")
                        && value.contains("Path=/") && value.contains("HttpOnly"))
                .anyMatch(value -> value.contains("refreshToken=refresh-value")
                        && value.contains("Path=/auth") && value.contains("HttpOnly"));
    }

    @Test
    void sessionPassesAbsentTokensToApplicationService() {
        AuthApplicationService applicationService = mock(AuthApplicationService.class);
        when(applicationService.session(null, null)).thenReturn(loggedOut(false));
        AuthController controller = controller(applicationService, mock(ClientIpResolver.class));

        LoginStatus status = controller.session(new MockHttpServletRequest());

        assertThat(status.isStatus()).isFalse();
        assertThat(status.isRefreshable()).isFalse();
        verify(applicationService).session(null, null);
    }

    @Test
    void sessionPassesRefreshTokenWithoutExposingItInTheResponse() {
        AuthApplicationService applicationService = mock(AuthApplicationService.class);
        when(applicationService.session(null, "private-refresh-value")).thenReturn(loggedOut(true));
        AuthController controller = controller(applicationService, mock(ClientIpResolver.class));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setCookies(new Cookie("refreshToken", "private-refresh-value"));

        LoginStatus status = controller.session(request);

        assertThat(status.isStatus()).isFalse();
        assertThat(status.isRefreshable()).isTrue();
        assertThat(status.getUserCode()).isNull();
        verify(applicationService).session(null, "private-refresh-value");
    }

    @Test
    void sessionUsesBearerTokenWhenAccessCookieIsAbsent() {
        AuthApplicationService applicationService = mock(AuthApplicationService.class);
        when(applicationService.session("invalid-token", null)).thenReturn(loggedOut(false));
        AuthController controller = controller(applicationService, mock(ClientIpResolver.class));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Authorization", "Bearer invalid-token");

        LoginStatus status = controller.session(request);

        assertThat(status.isStatus()).isFalse();
        verify(applicationService).session("invalid-token", null);
    }

    private AuthController controller(
            AuthApplicationService applicationService,
            ClientIpResolver clientIpResolver
    ) {
        return new AuthController(
                applicationService,
                new CookieProperties(),
                new JwtProperties(),
                clientIpResolver
        );
    }

    private LoginStatus loggedOut(boolean refreshable) {
        return LoginStatus.builder()
                .status(false)
                .refreshable(refreshable)
                .build();
    }
}
