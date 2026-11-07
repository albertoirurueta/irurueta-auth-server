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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.when;

import java.security.SecureRandom;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link SecureRandomOneTimeCodeGenerator}.
 */
@ExtendWith(MockitoExtension.class)
class SecureRandomOneTimeCodeGeneratorTest {

    /** Number of digits requested. */
    private static final int DIGITS = 6;

    /** Source of randomness. */
    @Mock
    private SecureRandom secureRandom;

    /** Generator under test. */
    @InjectMocks
    private SecureRandomOneTimeCodeGenerator generator;

    /**
     * Verifies that every digit is drawn separately, so leading zeros are kept.
     */
    @Test
    void generate_whenDigitsAreZero_keepsLeadingZeros() {
        when(secureRandom.nextInt(anyInt())).thenReturn(0, 0, 1, 2, 1, 1);

        assertEquals("001211", generator.generate(DIGITS));
    }

    /**
     * Verifies that a real generator yields numeric codes of the requested length.
     */
    @Test
    void generate_whenUsingARealRandom_returnsNumericCodeOfRequestedLength() {
        final var real = new SecureRandomOneTimeCodeGenerator(new SecureRandom());

        final var code = real.generate(DIGITS);

        assertEquals(DIGITS, code.length());
        assertTrue(code.chars().allMatch(Character::isDigit));
    }

    /**
     * Verifies that a non-positive length is rejected.
     */
    @Test
    void generate_whenDigitsIsNotPositive_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> generator.generate(0));
    }
}
