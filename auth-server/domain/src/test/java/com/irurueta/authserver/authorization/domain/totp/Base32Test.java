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

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link Base32}, with the vectors of RFC 4648 section 10 without their padding.
 */
class Base32Test {

    /**
     * Verifies that nothing encodes to nothing.
     */
    @Test
    void encode_whenInputIsEmpty_returnsEmptyText() {
        assertEquals("", Base32.encode(new byte[0]));
    }

    /**
     * Verifies the RFC 4648 vectors for every remainder length.
     */
    @Test
    void encode_whenRfcVector_returnsExpectedText() {
        assertEquals("MY", encode("f"));
        assertEquals("MZXQ", encode("fo"));
        assertEquals("MZXW6", encode("foo"));
        assertEquals("MZXW6YQ", encode("foob"));
        assertEquals("MZXW6YTB", encode("fooba"));
        assertEquals("MZXW6YTBOI", encode("foobar"));
    }

    /**
     * Verifies that high bytes are treated as unsigned.
     */
    @Test
    void encode_whenBytesAreNegative_returnsExpectedText() {
        assertEquals("74", Base32.encode(new byte[] {-1}));
    }

    /**
     * Encodes the ASCII bytes of a text.
     *
     * @param text the text.
     * @return the Base32 form.
     */
    private static String encode(final String text) {
        return Base32.encode(text.getBytes(StandardCharsets.US_ASCII));
    }
}
