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
package com.irurueta.authserver.authorization.domain.totp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.Arrays;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SecureRandomSecretGenerator}.
 */
class SecureRandomSecretGeneratorTest {

    /** Subject under test. */
    private final SecureRandomSecretGenerator generator = new SecureRandomSecretGenerator();

    /**
     * Verifies that a secret has 160 bits.
     */
    @Test
    void generate_whenCalled_returns160Bits() {
        assertEquals(SecureRandomSecretGenerator.SECRET_BYTES, generator.generate().length);
    }

    /**
     * Verifies that two secrets differ.
     */
    @Test
    void generate_whenCalledTwice_returnsDifferentSecrets() {
        assertFalse(Arrays.equals(generator.generate(), generator.generate()));
    }
}
