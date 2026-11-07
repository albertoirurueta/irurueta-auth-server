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

import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SmsSpendCap}.
 */
class SmsSpendCapTest {

    /** Window used by the tests. */
    private static final Duration WINDOW = Duration.ofHours(1);

    /** Cap used by the tests. */
    private static final long CAP = 1_000L;

    /**
     * Verifies that a valid cap keeps its values, and that a zero cap is allowed.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var cap = new SmsSpendCap(WINDOW, CAP);

        assertEquals(WINDOW, cap.window());
        assertEquals(CAP, cap.capMicros());
        assertEquals(0L, new SmsSpendCap(WINDOW, 0L).capMicros());
    }

    /**
     * Verifies that a missing, zero or negative window is rejected.
     */
    @Test
    void constructor_whenWindowIsNotPositive_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new SmsSpendCap(null, CAP));
        assertThrows(IllegalArgumentException.class, () -> new SmsSpendCap(Duration.ZERO, CAP));
        assertThrows(IllegalArgumentException.class, () -> new SmsSpendCap(WINDOW.negated(), CAP));
    }

    /**
     * Verifies that a negative cap is rejected.
     */
    @Test
    void constructor_whenCapIsNegative_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new SmsSpendCap(WINDOW, -1L));
    }
}
