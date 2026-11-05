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

package com.irurueta.authserver.authorization.infrastructure.keys;

import com.irurueta.authserver.authorization.domain.keys.SigningKey;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyGenerator;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyStatus;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

// tag::keys-encryption[]
/**
 * Generates RSA signing keys for the {@code RS256} algorithm. The identifier is a random UUID and the private half
 * leaves the generator already encrypted.
 */
@Component
@RequiredArgsConstructor
public class RsaSigningKeyGenerator implements SigningKeyGenerator {

    /** Size in bits of the generated RSA keys. */
    static final int KEY_SIZE = 2048;

    /** Algorithm the keys are used with. */
    static final String ALGORITHM = "RS256";

    /** Encrypts the private half. */
    private final AesGcmKeyCipher cipher;

    /**
     * Generates a key in the {@link SigningKeyStatus#NEXT} state.
     *
     * @param now instant at which it is generated.
     * @return the key.
     * @throws IllegalStateException if RSA is not available.
     */
    @Override
    public SigningKey generate(final Instant now) {
        final var keyId = UUID.randomUUID().toString();
        final var keyPair = generateKeyPair();
        final var publicKey = (RSAPublicKey) keyPair.getPublic();
        final var common = new RSAKey.Builder(publicKey)
                .keyID(keyId)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256);
        final var publicJwk = common.build().toJSONString();
        final var privateJwk = common.privateKey((RSAPrivateKey) keyPair.getPrivate()).build().toJSONString();
        return new SigningKey(keyId, ALGORITHM, publicJwk, cipher.encrypt(privateJwk), SigningKeyStatus.NEXT, now,
                null, null);
    }

    /**
     * Generates an RSA key pair.
     *
     * @return the key pair.
     */
    private static KeyPair generateKeyPair() {
        try {
            final var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(KEY_SIZE);
            return generator.generateKeyPair();
        } catch (final NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA is not available", e);
        }
    }
}
// end::keys-encryption[]
