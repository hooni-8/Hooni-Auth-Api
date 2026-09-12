package org.hooni.auth.api.service.auth;

import io.jsonwebtoken.JwtException;
import org.hooni.auth.api.common.exception.AuthException;
import org.hooni.auth.api.mapper.auth.AuthMapper;
import org.hooni.auth.api.model.auth.AuthTokens;
import org.hooni.auth.api.model.auth.request.LoginRequest;
import org.hooni.auth.api.model.user.UserDetail;
import org.hooni.auth.api.security.JwtTokenProvider;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthServiceTest {

    @Test
    void reportsRefreshableOnlyWhenJwtAndRedisSessionMatch() {
        AuthMapper mapper = mock(AuthMapper.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        JwtTokenProvider provider = mock(JwtTokenProvider.class);
        RefreshTokenService refreshTokens = mock(RefreshTokenService.class);
        AuthService service = new AuthService(mapper, encoder, provider, refreshTokens);
        when(provider.getRefreshTokenUserCode("valid-refresh")).thenReturn("user-code");
        when(refreshTokens.matches("user-code", "valid-refresh")).thenReturn(true);

        assertThat(service.isRefreshable("valid-refresh")).isTrue();
    }

    @Test
    void invalidRefreshJwtIsNotRefreshable() {
        AuthMapper mapper = mock(AuthMapper.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        JwtTokenProvider provider = mock(JwtTokenProvider.class);
        RefreshTokenService refreshTokens = mock(RefreshTokenService.class);
        AuthService service = new AuthService(mapper, encoder, provider, refreshTokens);
        when(provider.getRefreshTokenUserCode("invalid-refresh"))
                .thenThrow(new JwtException("invalid"));

        assertThat(service.isRefreshable("invalid-refresh")).isFalse();
    }

    @Test
    void rotatesRefreshTokenAndReturnsNewPair() {
        AuthMapper mapper = mock(AuthMapper.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        JwtTokenProvider provider = mock(JwtTokenProvider.class);
        RefreshTokenService refreshTokens = mock(RefreshTokenService.class);
        AuthService service = new AuthService(mapper, encoder, provider, refreshTokens);
        UserDetail user = UserDetail.builder().userCode("user-code").build();

        when(provider.getRefreshTokenUserCode("old-refresh")).thenReturn("user-code");
        when(mapper.findByUserCode("user-code")).thenReturn(user);
        when(provider.generateRefreshToken(user)).thenReturn("new-refresh");
        when(provider.generateAccessToken(user)).thenReturn("new-access");
        when(refreshTokens.rotate("user-code", "old-refresh", "new-refresh")).thenReturn(true);

        AuthTokens result = service.refresh("old-refresh");

        assertThat(result.accessToken()).isEqualTo("new-access");
        assertThat(result.refreshToken()).isEqualTo("new-refresh");
        verify(refreshTokens).rotate("user-code", "old-refresh", "new-refresh");
    }

    @Test
    void rejectsAlreadyRotatedRefreshToken() {
        AuthMapper mapper = mock(AuthMapper.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        JwtTokenProvider provider = mock(JwtTokenProvider.class);
        RefreshTokenService refreshTokens = mock(RefreshTokenService.class);
        AuthService service = new AuthService(mapper, encoder, provider, refreshTokens);
        UserDetail user = UserDetail.builder().userCode("user-code").build();

        when(provider.getRefreshTokenUserCode("replayed-refresh")).thenReturn("user-code");
        when(mapper.findByUserCode("user-code")).thenReturn(user);
        when(provider.generateRefreshToken(user)).thenReturn("next-refresh");
        when(refreshTokens.rotate("user-code", "replayed-refresh", "next-refresh")).thenReturn(false);

        assertThatThrownBy(() -> service.refresh("replayed-refresh"))
                .isInstanceOf(AuthException.class);
    }

    @Test
    void verifiesAgainstDummyHashWhenUserDoesNotExist() {
        AuthMapper mapper = mock(AuthMapper.class);
        PasswordEncoder encoder = mock(PasswordEncoder.class);
        JwtTokenProvider provider = mock(JwtTokenProvider.class);
        RefreshTokenService refreshTokens = mock(RefreshTokenService.class);
        AuthService service = new AuthService(mapper, encoder, provider, refreshTokens);
        LoginRequest request = new LoginRequest();
        request.setUserId("missing-user");
        request.setPassword("password1");

        when(mapper.findByUserId("missing-user")).thenReturn(null);

        assertThatThrownBy(() -> service.login(request))
                .isInstanceOf(AuthException.class);
        verify(encoder).matches(org.mockito.ArgumentMatchers.eq("password1"),
                org.mockito.ArgumentMatchers.anyString());
    }
}
