package org.hooni.auth.api.controller;

import io.jsonwebtoken.Jwts;
import org.hooni.auth.api.common.response.ApiResponseAdvice;
import org.hooni.auth.api.controller.v1.auth.JwkController;
import org.hooni.auth.api.model.user.UserDetail;
import org.hooni.auth.api.properties.JwtProperties;
import org.hooni.auth.api.security.JwtTokenProvider;
import org.hooni.auth.api.security.RsaKeyProvider;
import org.hooni.auth.api.service.auth.JwkService;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class JwkControllerTest {

    @Test
    void jwksKeepsTheStandardResponseShape() throws Exception {
        JwtProperties properties = new JwtProperties();
        RsaKeyProvider keys = new RsaKeyProvider(properties);
        JwkService jwkService = new JwkService(keys, properties);
        MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new JwkController(jwkService))
                .setControllerAdvice(new ApiResponseAdvice())
                .build();

        mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].n").isString())
                .andExpect(jsonPath("$.code").doesNotExist())
                .andExpect(jsonPath("$.data").doesNotExist());
    }

    @Test
    @SuppressWarnings("unchecked")
    void publishedJwkVerifiesTokenWithoutExposingPrivateKey() throws Exception {
        JwtProperties properties = new JwtProperties();
        RsaKeyProvider keys = new RsaKeyProvider(properties);
        JwtTokenProvider tokens = new JwtTokenProvider(properties, keys);
        Map<String, Object> response = new JwkController(new JwkService(keys, properties)).keys();

        Map<String, Object> jwk = ((List<Map<String, Object>>) response.get("keys")).get(0);
        RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(
                new RSAPublicKeySpec(
                        unsigned((String) jwk.get("n")),
                        unsigned((String) jwk.get("e"))
                )
        );
        String token = tokens.generateAccessToken(UserDetail.builder()
                .userCode("user-code")
                .userName("Hooni")
                .roleGroup("FREE_USER")
                .build());

        assertThat(jwk).containsEntry("alg", "RS256").containsEntry("use", "sig");
        assertThat(jwk).doesNotContainKeys("d", "p", "q");
        assertThat(Jwts.parser().verifyWith(publicKey).build().parseSignedClaims(token)
                .getPayload().get("userCode", String.class)).isEqualTo("user-code");
    }

    private BigInteger unsigned(String value) {
        return new BigInteger(1, Base64.getUrlDecoder().decode(value));
    }
}
