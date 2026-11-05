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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.keys.SigningKeyStatus;
import com.nimbusds.jose.jwk.RSAKey;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link RsaSigningKeyGenerator}.
 */
class RsaSigningKeyGeneratorTest {

    /** Instant passed to the generator. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Cipher the generator encrypts with. */
    private final AesGcmKeyCipher cipher = new AesGcmKeyCipher(KeyTestSupport.randomProperties());

    /** Generator under test. */
    private final RsaSigningKeyGenerator generator = new RsaSigningKeyGenerator(cipher);

    /**
     * Verifies the metadata of a generated key.
     */
    @Test
    void generate_whenCalled_returnsNextRs256KeyWithUuidIdentifier() {
        final var key = generator.generate(NOW);

        assertEquals(key.kid(), UUID.fromString(key.kid()).toString());
        assertEquals("RS256", key.alg());
        assertEquals(SigningKeyStatus.NEXT, key.status());
        assertEquals(NOW, key.createdAt());
        assertNull(key.activatedAt());
        assertNull(key.retiredAt());
    }

    /**
     * Verifies that the public half has no private material and the private half is only stored encrypted.
     *
     * @throws Exception if a key cannot be parsed.
     */
    @Test
    void generate_whenCalled_publishesPublicHalfAndEncryptsPrivateHalf() throws Exception {
        final var key = generator.generate(NOW);

        final var publicKey = (RSAKey) RSAKey.parse(key.publicJwk());
        final var privateKey = (RSAKey) RSAKey.parse(cipher.decrypt(key.encryptedPrivateJwk()));

        assertFalse(publicKey.isPrivate());
        assertTrue(privateKey.isPrivate());
        assertEquals(key.kid(), publicKey.getKeyID());
        assertEquals(key.kid(), privateKey.getKeyID());
        assertEquals(publicKey.toRSAPublicKey(), privateKey.toRSAPublicKey());
        assertEquals(RsaSigningKeyGenerator.KEY_SIZE, publicKey.toRSAPublicKey().getModulus().bitLength());
        assertFalse(key.encryptedPrivateJwk().contains(key.kid()));
    }

    /**
     * Verifies that two generated keys differ.
     */
    @Test
    void generate_whenCalledTwice_givesDifferentKeys() {
        assertNotEquals(generator.generate(NOW).kid(), generator.generate(NOW).kid());
    }
}
