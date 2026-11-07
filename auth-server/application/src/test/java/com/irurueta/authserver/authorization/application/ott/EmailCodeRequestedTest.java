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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Duration;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link EmailCodeRequested}.
 */
class EmailCodeRequestedTest {

    /** Address used by the tests. */
    private static final String ADDRESS = "alice@example.test";

    /** Code used by the tests. */
    private static final String CODE = "123456";

    /** Validity used by the tests. */
    private static final Duration VALID_FOR = Duration.ofMinutes(10);

    /**
     * Verifies that a valid event keeps its values.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var event = new EmailCodeRequested(ADDRESS, CODE, VALID_FOR);

        assertEquals(ADDRESS, event.address());
        assertEquals(CODE, event.code());
        assertEquals(VALID_FOR, event.validFor());
    }

    /**
     * Verifies that missing or blank values are rejected.
     */
    @Test
    void constructor_whenAValueIsMissing_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new EmailCodeRequested(null, CODE, VALID_FOR));
        assertThrows(IllegalArgumentException.class, () -> new EmailCodeRequested(" ", CODE, VALID_FOR));
        assertThrows(IllegalArgumentException.class, () -> new EmailCodeRequested(ADDRESS, null, VALID_FOR));
        assertThrows(IllegalArgumentException.class, () -> new EmailCodeRequested(ADDRESS, " ", VALID_FOR));
        assertThrows(IllegalArgumentException.class, () -> new EmailCodeRequested(ADDRESS, CODE, null));
    }

    /**
     * Verifies that the description carries neither the address nor the code.
     */
    @Test
    void toString_whenCalled_hidesTheAddressAndTheCode() {
        final var text = new EmailCodeRequested(ADDRESS, CODE, VALID_FOR).toString();

        assertFalse(text.contains(ADDRESS));
        assertFalse(text.contains(CODE));
    }
}
