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
package com.irurueta.authserver.authorization.domain;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Tests {@link Preconditions}.
 */
class PreconditionsTest {

    /**
     * A null, empty or whitespace-only text is blank.
     */
    @Test
    void isBlank_whenTextIsMissing_returnsTrue() {
        assertTrue(Preconditions.isBlank(null));
        assertTrue(Preconditions.isBlank(""));
        assertTrue(Preconditions.isBlank(" \t"));
    }

    /**
     * A text with a visible character is not blank.
     */
    @Test
    void isBlank_whenTextHasContent_returnsFalse() {
        assertFalse(Preconditions.isBlank(" a "));
    }

    /**
     * A present text is returned as it is.
     */
    @Test
    void requireText_whenTextHasContent_returnsIt() {
        assertEquals("value", Preconditions.requireText("value", "name"));
    }

    /**
     * A missing text is rejected with a message naming it.
     */
    @Test
    void requireText_whenTextIsBlank_throwsIllegalArgumentException() {
        final var error = assertThrows(IllegalArgumentException.class, () -> Preconditions.requireText(" ", "name"));
        assertEquals("name must not be blank", error.getMessage());
        assertThrows(IllegalArgumentException.class, () -> Preconditions.requireText(null, "name"));
    }

    /**
     * An optional text may be absent.
     */
    @Test
    void requireTextIfPresent_whenTextIsNull_returnsNull() {
        assertNull(Preconditions.requireTextIfPresent(null, "name"));
    }

    /**
     * An optional text that is present must not be blank.
     */
    @Test
    void requireTextIfPresent_whenTextIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> Preconditions.requireTextIfPresent("", "name"));
        assertEquals("value", Preconditions.requireTextIfPresent("value", "name"));
    }
}
