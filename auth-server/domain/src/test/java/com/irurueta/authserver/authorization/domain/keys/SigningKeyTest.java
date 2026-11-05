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

package com.irurueta.authserver.authorization.domain.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SigningKey}.
 */
class SigningKeyTest {

    /** Creation instant used by the tests. */
    private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

    /** Later instant used by the tests. */
    private static final Instant LATER = Instant.parse("2026-02-01T00:00:00Z");

    /** Key identifier used by the tests. */
    private static final String KID = "kid-1";

    /**
     * Verifies that valid values are kept.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var key = nextKey();

        assertEquals(KID, key.kid());
        assertEquals("RS256", key.alg());
        assertEquals(SigningKeyStatus.NEXT, key.status());
        assertEquals(CREATED_AT, key.createdAt());
        assertNull(key.activatedAt());
        assertNull(key.retiredAt());
    }

    /**
     * Verifies that blank texts are rejected.
     */
    @Test
    void constructor_whenATextIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new SigningKey(" ", "RS256", "pub", "priv",
                SigningKeyStatus.NEXT, CREATED_AT, null, null));
        assertThrows(IllegalArgumentException.class, () -> new SigningKey(KID, null, "pub", "priv",
                SigningKeyStatus.NEXT, CREATED_AT, null, null));
        assertThrows(IllegalArgumentException.class, () -> new SigningKey(KID, "RS256", "", "priv",
                SigningKeyStatus.NEXT, CREATED_AT, null, null));
        assertThrows(IllegalArgumentException.class, () -> new SigningKey(KID, "RS256", "pub", null,
                SigningKeyStatus.NEXT, CREATED_AT, null, null));
    }

    /**
     * Verifies that a missing status or creation instant is rejected.
     */
    @Test
    void constructor_whenStatusOrCreationIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new SigningKey(KID, "RS256", "pub", "priv", null,
                CREATED_AT, null, null));
        assertThrows(IllegalArgumentException.class, () -> new SigningKey(KID, "RS256", "pub", "priv",
                SigningKeyStatus.NEXT, null, null, null));
    }

    /**
     * Verifies that activating a key records the instant and the new state.
     */
    @Test
    void activate_whenCalled_returnsActiveKey() {
        final var active = nextKey().activate(LATER);

        assertEquals(SigningKeyStatus.ACTIVE, active.status());
        assertEquals(LATER, active.activatedAt());
        assertEquals(KID, active.kid());
    }

    /**
     * Verifies that retiring a key records the instant and the new state.
     */
    @Test
    void retire_whenCalled_returnsRetiredKey() {
        final var retired = nextKey().activate(LATER).retire(LATER);

        assertEquals(SigningKeyStatus.RETIRED, retired.status());
        assertEquals(LATER, retired.retiredAt());
        assertEquals(LATER, retired.activatedAt());
    }

    /**
     * Creates a key in the next state.
     *
     * @return the key.
     */
    private static SigningKey nextKey() {
        return new SigningKey(KID, "RS256", "pub", "priv", SigningKeyStatus.NEXT, CREATED_AT, null, null);
    }
}
