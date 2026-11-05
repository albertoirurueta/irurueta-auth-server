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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Unit tests of {@link SpringPasswordHasher}.
 */
@ExtendWith(MockitoExtension.class)
class SpringPasswordHasherTest {

    /** Clear-text value used by the tests; not a real credential. */
    private static final String RAW = "raw-value";

    /** Encoded value used by the tests. */
    private static final String ENCODED = "{argon2}encoded";

    /** Encoder the hasher delegates to. */
    @Mock
    private PasswordEncoder passwordEncoder;

    /** Hasher under test. */
    @InjectMocks
    private SpringPasswordHasher hasher;

    /**
     * Verifies that encoding is delegated to the encoder.
     */
    @Test
    void encode_whenCalled_returnsEncoderResult() {
        when(passwordEncoder.encode(RAW)).thenReturn(ENCODED);

        assertEquals(ENCODED, hasher.encode(RAW));
    }

    /**
     * Verifies that matching is delegated to the encoder.
     */
    @Test
    void matches_whenEncoderMatches_returnsTrue() {
        when(passwordEncoder.matches(RAW, ENCODED)).thenReturn(true);

        assertTrue(hasher.matches(RAW, ENCODED));
    }

    /**
     * Verifies that a mismatch is reported as such.
     */
    @Test
    void matches_whenEncoderDoesNotMatch_returnsFalse() {
        when(passwordEncoder.matches(RAW, ENCODED)).thenReturn(false);

        assertFalse(hasher.matches(RAW, ENCODED));
    }

    /**
     * Verifies that the upgrade decision is delegated to the encoder.
     */
    @Test
    void upgradeEncoding_whenEncoderRequestsIt_returnsTrue() {
        when(passwordEncoder.upgradeEncoding(ENCODED)).thenReturn(true);

        assertTrue(hasher.upgradeEncoding(ENCODED));
    }

    /**
     * Verifies that a current encoding is not flagged.
     */
    @Test
    void upgradeEncoding_whenEncoderDoesNotRequestIt_returnsFalse() {
        when(passwordEncoder.upgradeEncoding(ENCODED)).thenReturn(false);

        assertFalse(hasher.upgradeEncoding(ENCODED));
    }
}
