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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SecureTokenGenerator}.
 */
class SecureTokenGeneratorTest {

    /** Generator under test. */
    private final SecureTokenGenerator generator = new SecureTokenGenerator();

    /**
     * Generated tokens are URL-safe, long enough and different each time.
     */
    @Test
    void generate_whenCalledTwice_returnsDistinctUrlSafeTokens() {
        final var first = generator.generate();
        final var second = generator.generate();

        assertNotEquals(first, second);
        assertEquals(SecureTokenGenerator.TOKEN_BYTES, Base64.getUrlDecoder().decode(first).length);
        assertTrue(first.matches("[A-Za-z0-9_-]+"));
    }

    /**
     * The hash is deterministic and differs from the token.
     */
    @Test
    void hash_whenSameToken_isDeterministic() {
        final var token = generator.generate();

        assertEquals(generator.hash(token), generator.hash(token));
        assertNotEquals(token, generator.hash(token));
    }

    /**
     * Different tokens hash differently.
     */
    @Test
    void hash_whenDifferentTokens_differs() {
        assertNotEquals(generator.hash("a"), generator.hash("b"));
    }

    /**
     * An unknown algorithm is reported as an illegal state.
     */
    @Test
    void digest_whenAlgorithmIsUnknown_throwsIllegalStateException() {
        assertThrows(IllegalStateException.class, () -> SecureTokenGenerator.digest("unknown", "a"));
    }
}
