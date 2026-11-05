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

package com.irurueta.authserver.authorization.api.web.account;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link AccountRateLimitProperties}.
 */
class AccountRateLimitPropertiesTest {

    /** A valid window. */
    private static final Duration WINDOW = Duration.ofMinutes(15);

    /** A valid limit. */
    private static final int LIMIT = 5;

    /**
     * Verifies that a valid configuration is kept.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var properties = new AccountRateLimitProperties(true, WINDOW, LIMIT, LIMIT, LIMIT);

        assertEquals(WINDOW, properties.window());
        assertEquals(LIMIT, properties.perClient());
    }

    /**
     * Verifies that a window that is missing, zero or negative is rejected.
     */
    @Test
    void constructor_whenWindowIsNotPositive_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new AccountRateLimitProperties(true, null, LIMIT, LIMIT, LIMIT));
        assertThrows(IllegalArgumentException.class,
                () -> new AccountRateLimitProperties(true, Duration.ZERO, LIMIT, LIMIT, LIMIT));
        assertThrows(IllegalArgumentException.class,
                () -> new AccountRateLimitProperties(true, WINDOW.negated(), LIMIT, LIMIT, LIMIT));
    }

    /**
     * Verifies that a limit or a number of tracked keys below one is rejected.
     */
    @Test
    void constructor_whenALimitIsNotPositive_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new AccountRateLimitProperties(true, WINDOW, 0, LIMIT, LIMIT));
        assertThrows(IllegalArgumentException.class,
                () -> new AccountRateLimitProperties(true, WINDOW, LIMIT, 0, LIMIT));
        assertThrows(IllegalArgumentException.class,
                () -> new AccountRateLimitProperties(true, WINDOW, LIMIT, LIMIT, 0));
    }
}
