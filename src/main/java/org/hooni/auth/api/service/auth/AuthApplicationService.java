package org.hooni.auth.api.service.auth;

import lombok.RequiredArgsConstructor;
import org.hooni.auth.api.common.code.StatusCode;
import org.hooni.auth.api.common.exception.AuthException;
import org.hooni.auth.api.model.auth.AuthTokens;
import org.hooni.auth.api.model.auth.LoginStatus;
import org.hooni.auth.api.model.auth.request.LoginRequest;
import org.hooni.auth.api.model.auth.request.RegisterRequest;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Locale;

/**
 * Controller에서 전달받은 인증 요청의 흐름을 조정한다.
 * 요청 제한과 인증 도메인 로직을 한곳에서 실행해 Controller가 HTTP 처리에만 집중하게 한다.
 */
@Service
@RequiredArgsConstructor
public class AuthApplicationService {

    private final AuthService authService;
    private final AuthRateLimitService rateLimitService;

    /** IP별 회원가입 요청 횟수를 제한한 뒤 신규 회원을 저장한다. */
    public void register(RegisterRequest request, String clientIdentifier) {
        rateLimitService.check("register", clientIdentifier, 10, Duration.ofHours(1));
        authService.register(request);
    }

    /** IP별 중복 확인 요청 횟수를 제한한 뒤 아이디 사용 여부를 조회한다. */
    public boolean existsUserId(String userId, String clientIdentifier) {
        rateLimitService.check("register-exists", clientIdentifier, 60, Duration.ofMinutes(1));
        return authService.existsUserId(userId);
    }

    /** IP와 아이디별 로그인 요청을 제한하고, 성공하면 실패 횟수를 초기화한 뒤 토큰을 반환한다. */
    public AuthTokens login(LoginRequest request, String clientIdentifier) {
        String normalizedUserId = request.getUserId().toLowerCase(Locale.ROOT);
        rateLimitService.check("login-ip", clientIdentifier, 30, Duration.ofMinutes(1));
        rateLimitService.check("login-user", normalizedUserId, 10, Duration.ofMinutes(5));

        AuthTokens tokens = authService.login(request);
        rateLimitService.reset("login-user", normalizedUserId);
        return tokens;
    }

    /** IP별 갱신 요청을 제한하고 Refresh Token을 검증·회전해 새 토큰 쌍을 반환한다. */
    public AuthTokens refresh(String refreshToken, String clientIdentifier) {
        rateLimitService.check("refresh", clientIdentifier, 60, Duration.ofMinutes(1));
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new AuthException(HttpStatus.UNAUTHORIZED, StatusCode.UNAUTHORIZED);
        }
        return authService.refresh(refreshToken);
    }

    /**
     * Access Token이 유효하면 로그인 정보를 반환한다.
     * 토큰이 없거나 유효하지 않으면 401 대신 로그아웃 상태와 갱신 가능 여부를 반환한다.
     */
    public LoginStatus session(String accessToken, String refreshToken) {
        if (accessToken != null && !accessToken.isBlank()) {
            try {
                return authService.session(accessToken);
            } catch (AuthException ignored) {
                // 세션 확인에서는 만료·위조 Access Token을 정상적인 미로그인 상태로 처리한다.
            }
        }
        return loggedOutStatus(refreshToken);
    }

    /** Refresh 세션을 폐기하도록 인증 Service에 로그아웃을 위임한다. */
    public void logout(String refreshToken, String accessToken) {
        authService.logout(refreshToken, accessToken);
    }

    /** Refresh JWT와 Redis 세션이 모두 유효한지 확인해 로그아웃 상태를 생성한다. */
    private LoginStatus loggedOutStatus(String refreshToken) {
        return LoginStatus.builder()
                .status(false)
                .refreshable(authService.isRefreshable(refreshToken))
                .build();
    }
}
