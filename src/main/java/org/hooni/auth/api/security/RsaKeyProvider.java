package org.hooni.auth.api.security;

import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.hooni.auth.api.properties.JwtProperties;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

/** Auth API만 보유하는 RSA 개인키와 외부 검증 서비스에 공개할 공개키를 관리한다. */
@Slf4j
@Getter
@Component
public class RsaKeyProvider {

    private final PrivateKey privateKey;
    private final RSAPublicKey publicKey;
    private final String keyId;

    public RsaKeyProvider(JwtProperties properties) {
        try {
            if (isBlank(properties.getPrivateKey()) && isBlank(properties.getPublicKey())) {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
                generator.initialize(2048);
                KeyPair generated = generator.generateKeyPair();
                this.privateKey = generated.getPrivate();
                this.publicKey = (RSAPublicKey) generated.getPublic();
                this.keyId = properties.getKeyId() + "-" + UUID.randomUUID().toString().substring(0, 8);
                log.warn("JWT RSA key pair was generated for this process. Configure JWT_PRIVATE_KEY and JWT_PUBLIC_KEY in persistent environments.");
                return;
            }

            KeyFactory factory = KeyFactory.getInstance("RSA");
            this.privateKey = factory.generatePrivate(new PKCS8EncodedKeySpec(decode(properties.getPrivateKey())));
            PublicKey decodedPublicKey = factory.generatePublic(new X509EncodedKeySpec(decode(properties.getPublicKey())));
            this.publicKey = (RSAPublicKey) decodedPublicKey;
            this.keyId = properties.getKeyId();
        } catch (Exception exception) {
            throw new IllegalStateException("Unable to initialize JWT RSA key pair", exception);
        }
    }

    private byte[] decode(String value) {
        String normalized = value
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(normalized);
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
