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

package com.irurueta.authserver.authorization.application.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.util.Base64;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link TrustedDeviceTokens}.
 */
class TrustedDeviceTokensTest {

    /** Length of the hexadecimal SHA-256 hash. */
    private static final int HASH_LENGTH = 64;

    /** Hash of {@code abc}, from the SHA-256 test vectors. */
    private static final String ABC_HASH = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    /** Component under test. */
    private final TrustedDeviceTokens tokens = new TrustedDeviceTokens();

    /**
     * Verifies that tokens carry 256 random bits and differ from each other.
     */
    @Test
    void newToken_whenCalledTwice_returnsDifferent256BitTokens() {
        final var first = tokens.newToken();

        assertEquals(TrustedDeviceTokens.TOKEN_BYTES, Base64.getUrlDecoder().decode(first).length);
        assertNotEquals(first, tokens.newToken());
    }

    /**
     * Verifies that the hash is the SHA-256 of the token in lowercase hexadecimal.
     */
    @Test
    void hash_whenCalled_returnsSha256Hex() {
        assertEquals(ABC_HASH, tokens.hash("abc"));
        assertEquals(HASH_LENGTH, tokens.hash(tokens.newToken()).length());
    }
}
