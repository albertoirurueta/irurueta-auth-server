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
package com.irurueta.authserver.authorization.api.web.implicit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link DeviceRateLimitProperties}.
 */
class DeviceRateLimitPropertiesTest {

    /** A valid window. */
    private static final Duration WINDOW = Duration.ofMinutes(5);

    /** A valid limit. */
    private static final int LIMIT = 4;

    /** A valid number of tracked keys. */
    private static final int KEYS = 100;

    /**
     * Verifies that a valid configuration keeps its values.
     */
    @Test
    void constructor_whenValid_keepsTheValues() {
        final var properties = new DeviceRateLimitProperties(true, WINDOW, LIMIT, LIMIT + 1, KEYS);

        assertTrue(properties.enabled());
        assertEquals(WINDOW, properties.window());
        assertEquals(LIMIT, properties.perClient());
        assertEquals(LIMIT + 1, properties.perUser());
        assertEquals(KEYS, properties.maxTrackedKeys());
    }

    /**
     * Verifies that a missing window is refused.
     */
    @Test
    void constructor_whenWindowIsMissing_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new DeviceRateLimitProperties(true, null, LIMIT, LIMIT, KEYS));
    }

    /**
     * Verifies that a zero window is refused.
     */
    @Test
    void constructor_whenWindowIsZero_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new DeviceRateLimitProperties(true, Duration.ZERO, LIMIT, LIMIT, KEYS));
    }

    /**
     * Verifies that a negative window is refused.
     */
    @Test
    void constructor_whenWindowIsNegative_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new DeviceRateLimitProperties(true, WINDOW.negated(), LIMIT, LIMIT, KEYS));
    }

    /**
     * Verifies that a limit that is not positive is refused.
     */
    @Test
    void constructor_whenALimitIsNotPositive_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new DeviceRateLimitProperties(true, WINDOW, 0, LIMIT, KEYS));
        assertThrows(IllegalArgumentException.class, () -> new DeviceRateLimitProperties(true, WINDOW, LIMIT, 0, KEYS));
        assertThrows(IllegalArgumentException.class,
                () -> new DeviceRateLimitProperties(true, WINDOW, LIMIT, LIMIT, 0));
    }
}
