package org.hooni.auth.api.service.auth;

import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.hooni.auth.api.common.code.StatusCode;
import org.hooni.auth.api.common.exception.AuthException;
import org.hooni.auth.api.mapper.auth.AuthMapper;
import org.hooni.auth.api.model.auth.AuthTokens;
import org.hooni.auth.api.model.auth.LoginStatus;
import org.hooni.auth.api.model.auth.request.LoginRequest;
import org.hooni.auth.api.model.auth.request.RegisterRequest;
import org.hooni.auth.api.model.user.UserDetail;
import org.hooni.auth.api.security.JwtTokenProvider;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/** 회원 데이터와 JWT·Refresh 세션을 사용해 핵심 인증 규칙을 수행한다. */
@Service
@RequiredArgsConstructor
public class AuthService {
    
    private static final String DEFAULT_ROLE = "FREE_USER";
    
    // 존재하지 않는 아이디도 BCrypt 검증을 수행해 응답 시간으로 가입 여부가 드러나는 것을 줄인다.
    private static final String DUMMY_PASSWORD_HASH = new BCryptPasswordEncoder().encode(UUID.randomUUID().toString());

    private final AuthMapper authMapper;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenService refreshTokenService;

    /** 입력값을 정규화하고 아이디 중복을 확인한 뒤 비밀번호를 암호화해 회원을 저장한다. */
    @Transactional
    public void register(RegisterRequest request) {

        request.setUserId(request.getUserId().trim());
        request.setUserName(request.getUserName().trim());

        // 사전 조회는 빠른 오류 응답을 위한 것이며 동시 요청을 완전히 막지 못한다.
        // 최종 중복 방지는 AUTH_USER의 UNIQUE 제약조건이 담당한다.
        if (authMapper.existsByUserId(request.getUserId())) {
            throw new AuthException(HttpStatus.CONFLICT, StatusCode.DUPLICATE_USER_ID);
        }

        UserDetail user = UserDetail.builder()
                .userCode(UUID.randomUUID().toString())
                .userId(request.getUserId())
                .userPw(passwordEncoder.encode(request.getUserPassword()))
                .userName(request.getUserName())
                .roleGroup(DEFAULT_ROLE)
                .build();

        authMapper.insert(user);
    }

    /** 입력한 아이디가 이미 회원 테이블에 존재하는지 조회한다. */
    public boolean existsUserId(String userId) {
        return authMapper.existsByUserId(userId);
    }

    /** 아이디와 비밀번호를 검증하고 Access/Refresh Token을 발급해 Refresh 세션을 저장한다. */
    public AuthTokens login(LoginRequest request) {
        
        UserDetail user = authMapper.findByUserId(request.getUserId());
        
        String passwordHash = user == null || user.getUserPw() == null ? DUMMY_PASSWORD_HASH : user.getUserPw();
        
        boolean passwordMatches = passwordEncoder.matches(request.getPassword(), passwordHash);
        
        // 회원 정보가 null || 비밀번호 일치하지 않음
        if (user == null || !passwordMatches) {
            throw new AuthException(HttpStatus.UNAUTHORIZED, StatusCode.LOGIN_FAIL);
        }

        // jwt token 생성
        String accessToken = jwtTokenProvider.generateAccessToken(user);
        String refreshToken = jwtTokenProvider.generateRefreshToken(user);

        // 사용자 코드당 Redis 키가 하나이므로 새 로그인은 기존 Refresh Token을 무효화한다.
        refreshTokenService.save(user.getUserCode(), refreshToken);

        return new AuthTokens(accessToken, refreshToken);
    }

    /** Refresh Token을 검증하고 원자적으로 회전한 뒤 새로운 Access/Refresh Token을 반환한다. */
    public AuthTokens refresh(String refreshToken) {
        String userCode;
        try {
            userCode = jwtTokenProvider.getRefreshTokenUserCode(refreshToken);
        } catch (Exception exception) {
            throw new AuthException(HttpStatus.UNAUTHORIZED, StatusCode.UNAUTHORIZED);
        }

        UserDetail user = authMapper.findByUserCode(userCode);
        if (user == null) {
            throw new AuthException(HttpStatus.UNAUTHORIZED, StatusCode.UNAUTHORIZED);
        }

        String nextRefreshToken = jwtTokenProvider.generateRefreshToken(user);
        if (!refreshTokenService.rotate(userCode, refreshToken, nextRefreshToken)) {
            throw new AuthException(HttpStatus.UNAUTHORIZED, StatusCode.UNAUTHORIZED);
        }

        return new AuthTokens(
                jwtTokenProvider.generateAccessToken(user),
                nextRefreshToken
        );
    }

    /** Access Token의 서명과 Claim을 검증하고 토큰에 포함된 로그인 정보를 반환한다. */
    public LoginStatus session(String accessToken) {
        try {
            return jwtTokenProvider.parseAccessToken(accessToken);
        } catch (Exception exception) {
            throw new AuthException(HttpStatus.UNAUTHORIZED, StatusCode.UNAUTHORIZED);
        }
    }

    /** Refresh JWT가 유효하고 Redis에 저장된 현재 세션과 일치하는지 확인한다. */
    public boolean isRefreshable(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            return false;
        }
        try {
            String userCode = jwtTokenProvider.getRefreshTokenUserCode(refreshToken);
            return refreshTokenService.matches(userCode, refreshToken);
        } catch (JwtException | IllegalArgumentException exception) {
            return false;
        }
    }

    /** 사용 가능한 토큰에서 사용자 코드를 찾아 해당 사용자의 Refresh 세션을 멱등하게 삭제한다. */
    public void logout(String refreshToken, String accessToken) {
        // 로그아웃은 멱등 처리한다. 토큰이 없거나 만료되어도 쿠키 삭제 응답은 Controller에서 반환한다.
        String userCode = getUserCodeIgnoringInvalidToken(refreshToken, true);
        if (userCode == null) {
            userCode = getUserCodeIgnoringInvalidToken(accessToken, false);
        }
        if (userCode != null) {
            refreshTokenService.delete(userCode);
        }
    }

    /** 유효하지 않거나 만료된 토큰을 오류로 전파하지 않고 사용자 코드 또는 null로 변환한다. */
    private String getUserCodeIgnoringInvalidToken(String token, boolean refresh) {
        if (token == null || token.isBlank()) {
            return null;
        }
        try {
            return refresh
                    ? jwtTokenProvider.getRefreshTokenUserCode(token)
                    : jwtTokenProvider.getAccessTokenUserCode(token);
        } catch (Exception ignored) {
            return null;
        }
    }
}
