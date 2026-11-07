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

package com.irurueta.authserver.authorization.application.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link Sha256OneTimeCodeHasher}.
 */
class Sha256OneTimeCodeHasherTest {

    /** SHA-256 of the text {@code 123456}, a published test vector. */
    private static final String HASH_123456 = "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92";

    /** Hasher under test. */
    private final Sha256OneTimeCodeHasher hasher = new Sha256OneTimeCodeHasher();

    /**
     * Verifies the hash against a known SHA-256 value.
     */
    @Test
    void hash_whenCodeIsGiven_returnsLowerCaseHexSha256() {
        assertEquals(HASH_123456, hasher.hash("123456"));
    }

    /**
     * Verifies that the hash is stable and depends on the code.
     */
    @Test
    void hash_whenCodesDiffer_returnsDifferentHashes() {
        assertEquals(hasher.hash("000001"), hasher.hash("000001"));
        assertNotEquals(hasher.hash("000001"), hasher.hash("000002"));
    }

    /**
     * Verifies that the right code matches its hash.
     */
    @Test
    void matches_whenCodeCorrespondsToHash_returnsTrue() {
        assertTrue(hasher.matches("123456", HASH_123456));
    }

    /**
     * Verifies that a wrong code does not match.
     */
    @Test
    void matches_whenCodeDiffers_returnsFalse() {
        assertFalse(hasher.matches("123457", HASH_123456));
    }

    /**
     * Verifies that missing values never match.
     */
    @Test
    void matches_whenAValueIsNull_returnsFalse() {
        assertFalse(hasher.matches(null, HASH_123456));
        assertFalse(hasher.matches("123456", null));
    }
}
