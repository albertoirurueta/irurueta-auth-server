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

import java.nio.charset.StandardCharsets;

/**
 * Base32 encoding (RFC 4648) without padding, the form authenticator applications expect for a shared secret.
 */
public final class Base32 {

    /** The Base32 alphabet. */
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    /** Bits carried by each byte. */
    private static final int BITS_PER_BYTE = 8;

    /** Bits carried by each character. */
    private static final int BITS_PER_CHAR = 5;

    /** Mask selecting the bits of one byte, to read it as unsigned. */
    private static final int BYTE_MASK = 0xff;

    /** Mask selecting the bits of one character. */
    private static final int CHAR_MASK = 0x1f;

    /**
     * Not instantiable: a holder of static helpers.
     */
    private Base32() {
    }

    /**
     * Encodes bytes.
     *
     * @param data the bytes to encode; must not be {@code null}.
     * @return the encoded text, upper case and without padding.
     */
    public static String encode(final byte[] data) {
        final var result = new StringBuilder((data.length * BITS_PER_BYTE + BITS_PER_CHAR - 1) / BITS_PER_CHAR);
        var buffer = 0;
        var bits = 0;
        for (final var value : data) {
            buffer = buffer << BITS_PER_BYTE | value & BYTE_MASK;
            bits += BITS_PER_BYTE;
            while (bits >= BITS_PER_CHAR) {
                bits -= BITS_PER_CHAR;
                result.append(ALPHABET.charAt(buffer >> bits & CHAR_MASK));
            }
        }
        if (bits > 0) {
            result.append(ALPHABET.charAt(buffer << BITS_PER_CHAR - bits & CHAR_MASK));
        }
        return new String(result.toString().getBytes(StandardCharsets.US_ASCII), StandardCharsets.US_ASCII);
    }
}
