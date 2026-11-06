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

package com.irurueta.authserver.authorization.application.totp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link RecoveryCodes}.
 */
class RecoveryCodesTest {

    /** Component under test. */
    private final RecoveryCodes recoveryCodes = new RecoveryCodes();

    /**
     * Verifies that a code has the expected length and only Crockford characters.
     */
    @Test
    void newCode_whenCalled_returnsTenCrockfordCharacters() {
        final var code = recoveryCodes.newCode();

        assertEquals(RecoveryCodes.CODE_LENGTH, code.length());
        assertTrue(code.matches("[0-9A-HJKMNP-TV-Z]+"));
    }

    /**
     * Verifies that a typed code is upper-cased, stripped of separators and mapped to the Crockford look-alikes.
     */
    @Test
    void normalize_whenTypedWithSeparatorsAndLookAlikes_returnsTheCanonicalForm() {
        assertEquals("01110ABCDE", recoveryCodes.normalize("oi1l0-abc de"));
    }
}
