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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.Arrays;
import java.util.HexFormat;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link PurposeKeyDerivation}, with a secret generated at run time.
 */
class PurposeKeyDerivationTest {

    /** Size of a derived key in bytes. */
    private static final int KEY_BYTES = 32;

    /** Size of a derived salt in bytes. */
    private static final int SALT_BYTES = 32;

    /** A purpose label. */
    private static final String PURPOSE = "first-purpose";

    /** Another purpose label. */
    private static final String OTHER_PURPOSE = "second-purpose";

    /** Properties shared by the derivation under test. */
    private final KeyEncryptionProperties properties = KeyTestSupport.randomProperties();

    /** Derivation under test. */
    private final PurposeKeyDerivation derivation = new PurposeKeyDerivation(properties);

    /**
     * Verifies that one purpose always gets the same hex salt, of the size of an HMAC-SHA256, unlike the configured
     * one.
     */
    @Test
    void saltFor_whenCalledTwiceForOnePurpose_returnsTheSameHexSalt() {
        final var salt = derivation.saltFor(PURPOSE);

        assertEquals(salt, derivation.saltFor(PURPOSE));
        assertEquals(SALT_BYTES, HexFormat.of().parseHex(salt).length);
        assertNotEquals(properties.salt(), salt);
    }

    /**
     * Verifies that two purposes get different salts.
     */
    @Test
    void saltFor_whenPurposesDiffer_returnsDifferentSalts() {
        assertNotEquals(derivation.saltFor(PURPOSE), derivation.saltFor(OTHER_PURPOSE));
    }

    /**
     * Verifies that one purpose always gets the same 256-bit key.
     */
    @Test
    void keyFor_whenCalledTwiceForOnePurpose_returnsTheSameKey() {
        final var key = derivation.keyFor(PURPOSE);

        assertEquals(KEY_BYTES, key.length);
        assertArrayEquals(key, derivation.keyFor(PURPOSE));
    }

    /**
     * Verifies that two purposes, or two passphrases, get different keys.
     */
    @Test
    void keyFor_whenPurposeOrPassphraseDiffers_returnsDifferentKeys() {
        final var other = new PurposeKeyDerivation(
                new KeyEncryptionProperties(UUID.randomUUID().toString(), properties.salt()));

        assertFalse(Arrays.equals(derivation.keyFor(PURPOSE), derivation.keyFor(OTHER_PURPOSE)));
        assertFalse(Arrays.equals(derivation.keyFor(PURPOSE), other.keyFor(PURPOSE)));
    }
}
