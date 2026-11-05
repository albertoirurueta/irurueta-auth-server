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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link TemporaryJwkConfiguration}.
 */
class TemporaryJwkConfigurationTest {

    /** Configuration under test. */
    private final TemporaryJwkConfiguration configuration = new TemporaryJwkConfiguration();

    /**
     * Verifies that every source holds a private RSA key of the expected size.
     *
     * @throws Exception if the key cannot be read from the source.
     */
    @Test
    void jwkSource_whenCalled_holdsPrivateRsaKeyOfExpectedSize() throws Exception {
        final var key = firstKey();

        assertTrue(key.isPrivate());
        assertEquals(TemporaryJwkConfiguration.KEY_SIZE, key.toRSAPublicKey().getModulus().bitLength());
    }

    /**
     * Verifies that two sources hold different keys.
     *
     * @throws Exception if a key cannot be read from its source.
     */
    @Test
    void jwkSource_whenCalledTwice_generatesDistinctKeys() throws Exception {
        final var first = firstKey();
        final var second = firstKey();

        assertNotEquals(first.getKeyID(), second.getKeyID());
        assertNotEquals(first.toRSAPublicKey(), second.toRSAPublicKey());
    }

    /**
     * Reads the key of a freshly created source.
     *
     * @return the first key of the source.
     * @throws KeySourceException if the key cannot be read from the source.
     */
    private RSAKey firstKey() throws KeySourceException {
        final var selector = new JWKSelector(new JWKMatcher.Builder().build());
        return (RSAKey) configuration.jwkSource().get(selector, null).getFirst();
    }
}
