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

package com.irurueta.authserver.authorization.application.clients;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link ClientSecretGenerator}.
 */
class ClientSecretGeneratorTest {

    /** Generator under test. */
    private final ClientSecretGenerator generator = new ClientSecretGenerator();

    /**
     * Verifies that a secret encodes the expected number of random bytes.
     */
    @Test
    void generate_whenCalled_returnsUrlSafeSecretOfExpectedSize() {
        final var secret = generator.generate();

        assertEquals(ClientSecretGenerator.SECRET_BYTES, Base64.getUrlDecoder().decode(secret).length);
    }

    /**
     * Verifies that two secrets differ.
     */
    @Test
    void generate_whenCalledTwice_returnsDifferentSecrets() {
        assertNotEquals(generator.generate(), generator.generate());
    }
}
