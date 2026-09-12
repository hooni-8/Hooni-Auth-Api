package org.hooni.auth.api.security;

import io.jsonwebtoken.Jwts;
import org.hooni.auth.api.model.auth.LoginStatus;
import org.hooni.auth.api.model.user.UserDetail;
import org.hooni.auth.api.properties.JwtProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class JwtTokenProviderTest {

    private JwtProperties properties;
    private RsaKeyProvider keys;
    private JwtTokenProvider provider;

    @BeforeEach
    void setUp() {
        properties = properties();
        keys = new RsaKeyProvider(properties);
        provider = new JwtTokenProvider(properties, keys);
    }

    @Test
    void signsAccessTokenWithRs256AndKeyId() {
        String token = provider.generateAccessToken(user());

        var parsed = Jwts.parser().verifyWith(keys.getPublicKey()).build().parseSignedClaims(token);
        assertThat(parsed.getHeader().getAlgorithm()).isEqualTo("RS256");
        assertThat(parsed.getHeader().getKeyId()).isEqualTo(keys.getKeyId());
    }

    @Test
    void accessTokenContainsUserClaims() {
        LoginStatus status = provider.parseAccessToken(provider.generateAccessToken(user()));

        assertThat(status.isStatus()).isTrue();
        assertThat(status.getUserCode()).isEqualTo("user-code");
        assertThat(status.getName()).isEqualTo("Hooni");
        assertThat(status.getRole()).isEqualTo("FREE_USER");
    }

    @Test
    void refreshTokenCannotBeUsedAsAccessToken() {
        assertThatThrownBy(() -> provider.parseAccessToken(provider.generateRefreshToken(user())))
                .isInstanceOf(RuntimeException.class);
    }

    @Test
    void refreshTokensAreUniqueForTheSameUser() {
        assertThat(provider.generateRefreshToken(user()))
                .isNotEqualTo(provider.generateRefreshToken(user()));
    }

    @Test
    void rejectsTokenSignedByAnotherAuthKey() {
        JwtProperties otherProperties = properties();
        JwtTokenProvider otherProvider = new JwtTokenProvider(
                otherProperties,
                new RsaKeyProvider(otherProperties)
        );

        assertThatThrownBy(() -> provider.parseAccessToken(otherProvider.generateAccessToken(user())))
                .isInstanceOf(RuntimeException.class);
    }

    private UserDetail user() {
        return UserDetail.builder()
                .userCode("user-code")
                .userName("Hooni")
                .roleGroup("FREE_USER")
                .build();
    }

    private JwtProperties properties() {
        JwtProperties result = new JwtProperties();
        result.setAccessTokenValidity(Duration.ofMinutes(15));
        result.setRefreshTokenValidity(Duration.ofDays(7));
        return result;
    }
}
