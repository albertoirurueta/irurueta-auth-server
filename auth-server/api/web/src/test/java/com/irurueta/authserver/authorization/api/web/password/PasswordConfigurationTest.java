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

package com.irurueta.authserver.authorization.api.web.password;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link PasswordConfiguration}.
 */
class PasswordConfigurationTest {

    /** Clear-text value used to exercise the encoder; not a real credential. */
    private static final String RAW_VALUE = "clear-text-value";

    /** Configuration under test. */
    private final PasswordConfiguration configuration = new PasswordConfiguration();

    /**
     * Verifies that the encoder matches the value it encoded.
     */
    @Test
    void passwordEncoder_whenValueIsEncoded_matchesIt() {
        final var encoder = configuration.passwordEncoder();

        assertTrue(encoder.matches(RAW_VALUE, encoder.encode(RAW_VALUE)));
    }

    /**
     * Verifies that the encoder does not match a different value.
     */
    @Test
    void passwordEncoder_whenValueDiffers_doesNotMatchIt() {
        final var encoder = configuration.passwordEncoder();

        assertFalse(encoder.matches("other", encoder.encode(RAW_VALUE)));
    }
}
