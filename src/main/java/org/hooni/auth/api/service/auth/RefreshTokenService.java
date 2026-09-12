package org.hooni.auth.api.service.auth;

import lombok.RequiredArgsConstructor;
import org.hooni.auth.api.properties.JwtProperties;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

/** Refresh Token 원문 대신 해시를 Redis에 저장하고 세션의 저장·회전·폐기를 담당한다. */
@Service
@RequiredArgsConstructor
public class RefreshTokenService {
    // 사용자당 하나의 로그인 세션만 유지한다. 다중 기기 로그인을 지원하려면
    // 세션 식별자(jti 또는 deviceId)를 Redis 키에 포함해야 한다.
    private static final String KEY_PREFIX = "auth:refresh-token:";

    private final StringRedisTemplate redisTemplate;
    private final JwtProperties jwtProperties;

    private static final DefaultRedisScript<Long> ROTATE_SCRIPT = new DefaultRedisScript<>("""
            if redis.call('GET', KEYS[1]) == ARGV[1] then
                redis.call('SET', KEYS[1], ARGV[2], 'EX', ARGV[3])
                return 1
            end
            return 0
            """, Long.class);

    /** 사용자 코드에 현재 Refresh Token 해시를 만료 시간과 함께 저장한다. */
    public void save(String userCode, String refreshToken) {
        redisTemplate.opsForValue().set(
                KEY_PREFIX + userCode,
                hash(refreshToken),
                jwtProperties.getRefreshTokenValidity()
        );
    }

    /** 현재 토큰 해시가 일치할 때만 Lua 스크립트로 새 토큰 해시를 원자적으로 교체한다. */
    public boolean rotate(String userCode, String currentToken, String newToken) {
        Long result = redisTemplate.execute(
                ROTATE_SCRIPT,
                List.of(KEY_PREFIX + userCode),
                hash(currentToken),
                hash(newToken),
                String.valueOf(jwtProperties.getRefreshTokenValidity().toSeconds())
        );
        return Long.valueOf(1L).equals(result);
    }

    /** 전달받은 Refresh Token이 Redis에 저장된 현재 토큰과 일치하는지 확인한다. */
    public boolean matches(String userCode, String refreshToken) {
        String storedHash = redisTemplate.opsForValue().get(KEY_PREFIX + userCode);
        return storedHash != null && storedHash.equals(hash(refreshToken));
    }

    /** 사용자 코드에 연결된 Refresh 세션을 삭제한다. */
    public void delete(String userCode) {
        redisTemplate.delete(KEY_PREFIX + userCode);
    }

    /** Redis에 토큰 원문이 남지 않도록 Refresh Token을 SHA-256 해시로 변환한다. */
    private String hash(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available", exception);
        }
    }
}
