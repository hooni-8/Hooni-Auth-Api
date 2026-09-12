package org.hooni.auth.api.service.auth;

import lombok.RequiredArgsConstructor;
import org.hooni.auth.api.common.code.StatusCode;
import org.hooni.auth.api.common.exception.AuthException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;

/** Redis 카운터를 사용해 인증 엔드포인트의 반복 요청을 제한한다. */
@Service
@RequiredArgsConstructor
public class AuthRateLimitService {
    private static final String KEY_PREFIX = "auth:rate-limit:";
    private static final DefaultRedisScript<Long> INCREMENT_SCRIPT = new DefaultRedisScript<>("""
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then
                redis.call('PEXPIRE', KEYS[1], ARGV[1])
            end
            return count
            """, Long.class);

    private final StringRedisTemplate redisTemplate;

    /** 범위와 식별자별 횟수를 원자적으로 증가시키고 설정된 한도를 넘으면 429 오류를 발생시킨다. */
    public void check(String scope, String identifier, long limit, Duration window) {
        String key = key(scope, identifier);
        Long count = redisTemplate.execute(
                INCREMENT_SCRIPT,
                java.util.List.of(key),
                Long.toString(window.toMillis())
        );
        if (count == null || count > limit) {
            throw new AuthException(HttpStatus.TOO_MANY_REQUESTS, StatusCode.TOO_MANY_REQUESTS);
        }
    }

    /** 지정한 범위와 식별자의 요청 제한 카운터를 삭제한다. */
    public void reset(String scope, String identifier) {
        redisTemplate.delete(key(scope, identifier));
    }

    /** 원문 식별자를 노출하지 않는 Redis 키를 생성한다. */
    private String key(String scope, String identifier) {
        return KEY_PREFIX + scope + ":" + hash(identifier);
    }

    /** IP나 아이디 등의 식별자를 SHA-256 해시 문자열로 변환한다. */
    private String hash(String value) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest.getInstance("SHA-256")
                            .digest(value.getBytes(StandardCharsets.UTF_8))
            );
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is not available", exception);
        }
    }
}
