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
package com.irurueta.authserver.authorization.api.web.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Duration;
import org.junit.jupiter.api.Test;

/** Unit tests of {@link OttRateLimitProperties}. */
class OttRateLimitPropertiesTest {

    /** Test fixture. */
    private static final Duration WINDOW = Duration.ofMinutes(5);

    /** Test fixture. */
    private static final int LIMIT = 3;

    /** Test fixture. */
    private static final int LAST = LIMIT + 3;

    /** Test fixture. */
    private static final int KEYS = 10;

    /** Valid values are kept. */
    @Test
    void constructor_whenValid_keepsTheValues() {
        final var properties = new OttRateLimitProperties(true, WINDOW, LIMIT, LIMIT + 1, LIMIT + 2, LAST, KEYS);

        assertTrue(properties.enabled());
        assertEquals(WINDOW, properties.window());
        assertEquals(LIMIT, properties.generationPerClient());
        assertEquals(LIMIT + 1, properties.generationPerIdentifier());
        assertEquals(LIMIT + 2, properties.verificationPerClient());
        assertEquals(LAST, properties.verificationPerIdentifier());
        assertEquals(KEYS, properties.maxTrackedKeys());
    }

    /** A missing, zero or negative window is refused. */
    @Test
    void constructor_whenWindowIsNotPositive_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new OttRateLimitProperties(true, null, LIMIT, LIMIT, LIMIT, LIMIT, KEYS));
        assertThrows(IllegalArgumentException.class,
                () -> new OttRateLimitProperties(true, Duration.ZERO, LIMIT, LIMIT, LIMIT, LIMIT, KEYS));
        assertThrows(IllegalArgumentException.class,
                () -> new OttRateLimitProperties(true, WINDOW.negated(), LIMIT, LIMIT, LIMIT, LIMIT, KEYS));
    }

    /** Every limit and the number of tracked keys must be positive. */
    @Test
    void constructor_whenALimitIsNotPositive_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new OttRateLimitProperties(true, WINDOW, 0, LIMIT, LIMIT, LIMIT, KEYS));
        assertThrows(IllegalArgumentException.class,
                () -> new OttRateLimitProperties(true, WINDOW, LIMIT, 0, LIMIT, LIMIT, KEYS));
        assertThrows(IllegalArgumentException.class,
                () -> new OttRateLimitProperties(true, WINDOW, LIMIT, LIMIT, 0, LIMIT, KEYS));
        assertThrows(IllegalArgumentException.class,
                () -> new OttRateLimitProperties(true, WINDOW, LIMIT, LIMIT, LIMIT, 0, KEYS));
        assertThrows(IllegalArgumentException.class,
                () -> new OttRateLimitProperties(true, WINDOW, LIMIT, LIMIT, LIMIT, LIMIT, 0));
    }
}
