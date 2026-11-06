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

import java.security.SecureRandom;
import java.util.Locale;
import org.springframework.stereotype.Component;

/**
 * Creates recovery codes (Crockford base-32 alphabet, so no {@code I}, {@code L}, {@code O} or {@code U}) and
 * normalizes what a user types back into that form.
 */
@Component
public class RecoveryCodes {

    /** Number of characters of a code. */
    public static final int CODE_LENGTH = 10;

    /** Crockford's base-32 alphabet. */
    private static final String ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

    /** Source of randomness. */
    private final SecureRandom random = new SecureRandom();

    /**
     * Creates a new random code.
     *
     * @return the code, {@link #CODE_LENGTH} characters long.
     */
    public String newCode() {
        final var code = new StringBuilder(CODE_LENGTH);
        for (var i = 0; i < CODE_LENGTH; i++) {
            code.append(ALPHABET.charAt(random.nextInt(ALPHABET.length())));
        }
        return code.toString();
    }

    /**
     * Normalizes a typed code: upper case, without separators, and with the look-alike letters Crockford maps
     * ({@code O} to {@code 0}, {@code I} and {@code L} to {@code 1}).
     *
     * @param typed the code as typed.
     * @return the canonical form.
     */
    public String normalize(final String typed) {
        return typed.toUpperCase(Locale.ROOT)
                .replace("-", "")
                .replace(" ", "")
                .replace('O', '0')
                .replace('I', '1')
                .replace('L', '1');
    }
}
