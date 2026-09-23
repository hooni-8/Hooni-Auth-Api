package org.hooni.auth.api.controller.v1.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.hooni.auth.api.model.auth.AuthTokens;
import org.hooni.auth.api.model.auth.LoginStatus;
import org.hooni.auth.api.model.auth.request.LoginRequest;
import org.hooni.auth.api.model.auth.request.RegisterExistsIdRequest;
import org.hooni.auth.api.model.auth.request.RegisterRequest;
import org.hooni.auth.api.model.auth.response.RegisterExistsIdResponse;
import org.hooni.auth.api.properties.CookieProperties;
import org.hooni.auth.api.properties.JwtProperties;
import org.hooni.auth.api.security.ClientIpResolver;
import org.hooni.auth.api.service.auth.AuthApplicationService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;

/** 인증 HTTP 요청을 Service 호출로 연결하고 토큰 쿠키를 생성·삭제한다. */
@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthApplicationService authApplicationService;
    private final CookieProperties cookieProperties;
    private final JwtProperties jwtProperties;
    private final ClientIpResolver clientIpResolver;

    /** 회원가입 요청과 클라이언트 식별자를 Service에 전달하고 HTTP 201을 반환한다. */
    @PostMapping("/register")
    public ResponseEntity<Void> register(
            @Valid @RequestBody RegisterRequest request,
            HttpServletRequest servletRequest
    ) {
        authApplicationService.register(request, clientIdentifier(servletRequest));
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    /** 입력한 아이디의 중복 여부를 조회해 응답 DTO로 반환한다. */
    @PostMapping("/register/exists")
    public RegisterExistsIdResponse existsUserId(@Valid @RequestBody RegisterExistsIdRequest request,HttpServletRequest servletRequest) {
        boolean exists = authApplicationService.existsUserId(
                request.getUserId(),
                clientIdentifier(servletRequest)
        );
        return new RegisterExistsIdResponse(exists);
    }

    /** 로그인 성공 시 발급된 Access/Refresh Token을 각각 HttpOnly 쿠키로 전달한다. */
    @PostMapping("/login")
    public ResponseEntity<Void> login(@Valid @RequestBody LoginRequest request, HttpServletRequest servletRequest) {
        log.info("sourcePath => {}", request.getSourcePath());
        AuthTokens tokens = authApplicationService.login(request, clientIdentifier(servletRequest));
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, accessTokenCookie(tokens.accessToken()).toString())
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie(tokens.refreshToken()).toString())
                .build();
    }

    /** Refresh Token 쿠키를 Service에 전달하고 회전된 토큰 쿠키 두 개를 다시 설정한다. */
    @PostMapping("/refresh")
    public ResponseEntity<Void> refresh(HttpServletRequest request) {
        String refreshToken = getCookie(request, cookieProperties.getRefreshTokenName());
        AuthTokens tokens = authApplicationService.refresh(refreshToken, clientIdentifier(request));
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, accessTokenCookie(tokens.accessToken()).toString())
                .header(HttpHeaders.SET_COOKIE, refreshTokenCookie(tokens.refreshToken()).toString())
                .build();
    }

    /** 쿠키 또는 Bearer 헤더의 Access Token과 Refresh Token으로 현재 로그인 상태를 조회한다. */
    @PostMapping("/session")
    public LoginStatus session(HttpServletRequest request) {
        return authApplicationService.session(
                getAccessToken(request),
                getCookie(request, cookieProperties.getRefreshTokenName())
        );
    }

    /** 서버의 Refresh 세션을 폐기하고 브라우저의 인증 쿠키를 만료시킨다. */
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletRequest request) {
        authApplicationService.logout(
                getCookie(request, cookieProperties.getRefreshTokenName()),
                getCookie(request, cookieProperties.getAccessTokenName())
        );
        return ResponseEntity.ok()
                .header(HttpHeaders.SET_COOKIE, deleteCookie(cookieProperties.getAccessTokenName(), "/").toString())
                .header(HttpHeaders.SET_COOKIE, deleteCookie(cookieProperties.getRefreshTokenName(), "/auth").toString())
                .build();
    }

    /** 루트 경로 전체에 전달되는 Access Token 쿠키를 생성한다. */
    private ResponseCookie accessTokenCookie(String token) {
        return cookie(
                cookieProperties.getAccessTokenName(),
                token,
                "/",
                jwtProperties.getAccessTokenValidity().getSeconds()
        );
    }

    /** 갱신과 로그아웃 경로에만 전달되는 Refresh Token 쿠키를 생성한다. */
    private ResponseCookie refreshTokenCookie(String token) {
        return cookie(
                cookieProperties.getRefreshTokenName(),
                token,
                "/auth",
                jwtProperties.getRefreshTokenValidity().getSeconds()
        );
    }

    /** 보안 속성과 만료 시간을 동일한 정책으로 적용해 HttpOnly 쿠키를 생성한다. */
    private ResponseCookie cookie(String name, String value, String path, long maxAgeSeconds) {
        return ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(cookieProperties.isSecure())
                .sameSite(cookieProperties.getSameSite())
                .path(path)
                .maxAge(maxAgeSeconds)
                .build();
    }

    /** 생성할 때와 동일한 속성으로 Max-Age 0 쿠키를 만들어 브라우저 쿠키를 삭제한다. */
    private ResponseCookie deleteCookie(String name, String path) {
        return cookie(name, "", path, 0);
    }

    /** Access Token 쿠키를 우선 사용하고, 없으면 Bearer Authorization 헤더를 사용한다. */
    private String getAccessToken(HttpServletRequest request) {
        String accessToken = getCookie(request, cookieProperties.getAccessTokenName());
        if (accessToken != null) {
            return accessToken;
        }

        String authorization = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authorization != null && authorization.startsWith("Bearer ")) {
            return authorization.substring(7);
        }
        return null;
    }

    /** 요청 쿠키 중 지정한 이름의 값을 찾아 반환한다. */
    private String getCookie(HttpServletRequest request, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        return Arrays.stream(cookies)
                .filter(cookie -> name.equals(cookie.getName()))
                .map(Cookie::getValue)
                .findFirst()
                .orElse(null);
    }

    /** 신뢰 프록시 설정을 반영한 클라이언트 IP 식별자를 생성한다. */
    private String clientIdentifier(HttpServletRequest request) {
        return clientIpResolver.resolve(request);
    }
}
