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
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link TotpUri}.
 */
class TotpUriTest {

    /** Secret used by the tests. */
    private static final byte[] SECRET = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);

    /** Base32 form of {@link #SECRET}. */
    private static final String ENCODED_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    /**
     * Verifies the whole URI, including the encoding of spaces and of the at sign.
     */
    @Test
    void build_whenValuesAreValid_returnsOtpauthUri() {
        assertEquals("otpauth://totp/Example%20Issuer:alice%40example.com?secret=" + ENCODED_SECRET
                        + "&issuer=Example%20Issuer&period=30&digits=6&algorithm=SHA1",
                TotpUri.build("Example Issuer", "alice@example.com", SECRET));
    }

    /**
     * Verifies that a blank issuer is rejected.
     */
    @Test
    void build_whenIssuerIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> TotpUri.build(" ", "alice", SECRET));
    }

    /**
     * Verifies that a blank account is rejected.
     */
    @Test
    void build_whenAccountIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> TotpUri.build("Issuer", null, SECRET));
    }
}
