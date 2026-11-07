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

import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeGenerator;
import java.security.SecureRandom;
import lombok.RequiredArgsConstructor;

/**
 * Generates numeric one-time codes with a cryptographically strong random number generator. Every digit is drawn
 * independently and uniformly, so leading zeros are kept ({@code 004217}).
 */
@RequiredArgsConstructor
public class SecureRandomOneTimeCodeGenerator implements OneTimeCodeGenerator {

    /** Number of decimal digits. */
    private static final int RADIX = 10;

    /** Source of randomness. */
    private final SecureRandom secureRandom;

    /**
     * Generates a code.
     *
     * @param digits number of digits, at least one.
     * @return the zero-padded code.
     * @throws IllegalArgumentException if {@code digits} is not positive.
     */
    @Override
    public String generate(final int digits) {
        if (digits <= 0) {
            throw new IllegalArgumentException("digits must be positive");
        }
        final var code = new StringBuilder(digits);
        for (var i = 0; i < digits; i++) {
            code.append(secureRandom.nextInt(RADIX));
        }
        return code.toString();
    }
}
