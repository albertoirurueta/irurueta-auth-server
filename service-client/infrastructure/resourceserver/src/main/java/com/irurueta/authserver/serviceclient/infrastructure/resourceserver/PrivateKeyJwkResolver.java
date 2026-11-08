/*
 * Copyright (C) 2026 Alberto Irurueta Carro (alberto@irurueta.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package com.irurueta.authserver.serviceclient.infrastructure.resourceserver;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import java.util.function.Function;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/**
 * Resolves the key that signs the {@code private_key_jwt} assertion: the unencrypted PKCS#8 PEM RSA private key of
 * {@link ServiceClientKeyProperties}, with its public half derived from it and the {@code RS256} algorithm. Neither
 * the messages nor the exceptions carry any part of the key.
 */
@Component
@RequiredArgsConstructor
public class PrivateKeyJwkResolver implements Function<ClientRegistration, JWK> {

    /** Marker of a PEM header or footer line. */
    private static final String PEM_MARKER = "-----[A-Z ]+-----";

    /** Header of a PKCS#1 key, which is not supported. */
    private static final String PKCS1_HEADER = "BEGIN RSA PRIVATE KEY";

    /** Settings of the key. */
    private final ServiceClientKeyProperties properties;

    // tag::private-key-jwt-client[]
    /**
     * Reads the key and builds its JWK.
     *
     * @param registration the registration the assertion is for, which is not needed to choose the key.
     * @return the signing JWK.
     * @throws IllegalStateException if no key is configured or it cannot be read as an unencrypted PKCS#8 RSA key.
     */
    @Override
    public JWK apply(final ClientRegistration registration) {
        final var pem = readPem();
        if (pem.contains(PKCS1_HEADER)) {
            throw new IllegalStateException("The private key must be PKCS#8 (BEGIN PRIVATE KEY), not PKCS#1");
        }
        try {
            final var der = Base64.getDecoder().decode(pem.replaceAll(PEM_MARKER, "").replaceAll("\\s", ""));
            final var factory = KeyFactory.getInstance("RSA");
            if (!(factory.generatePrivate(new PKCS8EncodedKeySpec(der)) instanceof RSAPrivateCrtKey privateKey)) {
                throw new IllegalStateException("The private key is not an RSA private key with CRT parameters");
            }
            final var publicKey = (RSAPublicKey) factory.generatePublic(
                    new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent()));
            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyID(properties.keyId())
                    .build();
        } catch (final IllegalArgumentException | GeneralSecurityException e) {
            throw new IllegalStateException("The private key is not a valid unencrypted PKCS#8 RSA key", e);
        }
    }
    // end::private-key-jwt-client[]

    /**
     * Reads the PEM text from the inline value or the file.
     *
     * @return the PEM text.
     */
    private String readPem() {
        if (StringUtils.hasText(properties.privateKey())) {
            return properties.privateKey().replace("\\n", "\n");
        }
        if (properties.privateKeyPath() == null) {
            throw new IllegalStateException(
                    "No private key: set service-client.auth.key.private-key or ...private-key-path");
        }
        try {
            return Files.readString(properties.privateKeyPath());
        } catch (final IOException e) {
            throw new IllegalStateException("The private key file cannot be read", e);
        }
    }
}
