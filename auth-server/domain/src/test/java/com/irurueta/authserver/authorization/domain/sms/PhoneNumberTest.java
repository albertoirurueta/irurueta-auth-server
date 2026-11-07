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
package com.irurueta.authserver.authorization.domain.sms;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link PhoneNumber}.
 */
class PhoneNumberTest {

    /**
     * Verifies that an E.164 number is kept.
     */
    @Test
    void constructor_whenNumberIsE164_keepsIt() {
        assertEquals("+34600123456", new PhoneNumber("+34600123456").e164());
    }

    /**
     * Verifies the shortest and longest accepted numbers.
     */
    @Test
    void constructor_whenNumberHasBoundaryLength_isAccepted() {
        assertEquals("+1234567", new PhoneNumber("+1234567").e164());
        assertEquals("+123456789012345", new PhoneNumber("+123456789012345").e164());
    }

    /**
     * Verifies that a missing number is rejected.
     */
    @Test
    void constructor_whenNumberIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new PhoneNumber(null));
    }

    /**
     * Verifies that a number without the plus sign is rejected.
     */
    @Test
    void constructor_whenPlusIsMissing_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new PhoneNumber("34600123456"));
    }

    /**
     * Verifies that a number starting with zero is rejected.
     */
    @Test
    void constructor_whenFirstDigitIsZero_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new PhoneNumber("+0600123456"));
    }

    /**
     * Verifies that a too short number is rejected.
     */
    @Test
    void constructor_whenNumberIsTooShort_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new PhoneNumber("+123456"));
    }

    /**
     * Verifies that a too long number is rejected.
     */
    @Test
    void constructor_whenNumberIsTooLong_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new PhoneNumber("+1234567890123456"));
    }

    /**
     * Verifies that separators are rejected.
     */
    @Test
    void constructor_whenNumberHasSeparators_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new PhoneNumber("+34 600 123 456"));
    }
}
