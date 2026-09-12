package org.hooni.auth.api.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.hooni.auth.api.model.auth.LoginStatus;
import org.hooni.auth.api.model.user.UserDetail;
import org.hooni.auth.api.properties.JwtProperties;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Duration;
import java.util.Date;
import java.util.Collection;
import java.util.UUID;

/**
 * 로그인 사용자에게 Access/Refresh Token을 발급하고 각 토큰의 용도와 필수 claim을 검증한다.
 * 개인키는 Auth API에만 존재하며 Gateway 및 하위 API는 JWKS 공개키로 검증한다.
 */
@Component
public class JwtTokenProvider {
    // subject를 토큰 용도 구분자로 사용한다. Refresh Token을 Access Token으로
    // 오용하지 못하도록 모든 파싱 진입점에서 기대 subject를 반드시 검증한다.
    private static final String ACCESS_SUBJECT = "accessToken";
    private static final String REFRESH_SUBJECT = "refreshToken";

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final String keyId;
    private final JwtProperties jwtProperties;

    public JwtTokenProvider(JwtProperties jwtProperties, RsaKeyProvider keyProvider) {
        this.jwtProperties = jwtProperties;
        this.privateKey = keyProvider.getPrivateKey();
        this.publicKey = keyProvider.getPublicKey();
        this.keyId = keyProvider.getKeyId();
    }

    public String generateAccessToken(UserDetail user) {
        return createToken(user, jwtProperties.getAccessTokenValidity(), ACCESS_SUBJECT);
    }

    public String generateRefreshToken(UserDetail user) {
        return createToken(user, jwtProperties.getRefreshTokenValidity(), REFRESH_SUBJECT);
    }

    public LoginStatus parseAccessToken(String token) {
        Claims claims = parseClaims(token, ACCESS_SUBJECT);
        return LoginStatus.builder()
                .status(true)
                .userCode(claims.get("userCode", String.class))
                .name(claims.get("userName", String.class))
                .role(claims.get("role", String.class))
                .build();
    }

    public String getAccessTokenUserCode(String token) {
        return parseClaims(token, ACCESS_SUBJECT).get("userCode", String.class);
    }

    public String getRefreshTokenUserCode(String token) {
        return parseClaims(token, REFRESH_SUBJECT).get("userCode", String.class);
    }

    private String createToken(UserDetail user, Duration validity, String subject) {
        Date issuedAt = new Date();
        return Jwts.builder()
                .header().keyId(keyId).and()
                .id(UUID.randomUUID().toString())
                .subject(subject)
                .issuer(jwtProperties.getIssuer())
                .claim("aud", jwtProperties.getAudience())
                .claim("userCode", user.getUserCode())
                .claim("userName", user.getUserName())
                // 권한 변경은 이미 발급된 Access Token이 만료된 뒤 반영된다.
                .claim("role", user.getRoleGroup())
                .issuedAt(issuedAt)
                .expiration(new Date(issuedAt.getTime() + validity.toMillis()))
                .signWith(privateKey, Jwts.SIG.RS256)
                .compact();
    }

    private Claims parseClaims(String token, String expectedSubject) {
        Jws<Claims> signedClaims = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(token);
        if (!"RS256".equals(signedClaims.getHeader().getAlgorithm())) {
            throw new JwtException("Unexpected token algorithm");
        }
        Claims claims = signedClaims.getPayload();

        if (!expectedSubject.equals(claims.getSubject())) {
            throw new JwtException("Unexpected token subject");
        }
        if (!jwtProperties.getIssuer().equals(claims.getIssuer())) {
            throw new JwtException("Unexpected token issuer");
        }
        if (!containsAudience(claims.get("aud"), jwtProperties.getAudience())) {
            throw new JwtException("Unexpected token audience");
        }
        if (claims.getExpiration() == null) {
            throw new JwtException("Token expiration is required");
        }
        if (claims.getId() == null || claims.getId().isBlank()) {
            throw new JwtException("Token id is required");
        }
        requireTextClaim(claims, "userCode");
        requireRoleClaim(claims);
        return claims;
    }

    private String requireTextClaim(Claims claims, String name) {
        String value = claims.get(name, String.class);
        if (value == null || value.isBlank()) {
            throw new JwtException("Token claim is required: " + name);
        }
        return value;
    }

    private String requireRoleClaim(Claims claims) {
        String role = requireTextClaim(claims, "role");
        if (!role.matches("[A-Z][A-Z0-9_]{0,63}")) {
            throw new JwtException("Invalid role claim");
        }
        return role;
    }

    private boolean containsAudience(Object claim, String expectedAudience) {
        if (claim instanceof String audience) {
            return expectedAudience.equals(audience);
        }
        if (claim instanceof Collection<?> audiences) {
            return audiences.contains(expectedAudience);
        }
        return false;
    }
}
