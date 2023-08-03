package com.zakaria.users.config;

import org.bouncycastle.asn1.eac.RSAPublicKey;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "rsa")
public record RsaKeysConfig(RSAPublicKey rsaPublicKey, RSAPrivateKey rsaPrivateKey) {
}
