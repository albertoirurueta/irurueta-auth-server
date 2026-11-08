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

package com.irurueta.authserver.authorization.domain.clientauth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link ClientAssertionUse}.
 */
class ClientAssertionUseTest {

    /** Client identifier. */
    private static final String CLIENT_ID = "client";

    /** Assertion identifier. */
    private static final String JTI = "jti-1";

    /** Expiry. */
    private static final Instant EXPIRES_AT = Instant.parse("2026-01-10T00:05:00Z");

    /**
     * Verifies that valid values are kept.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var use = new ClientAssertionUse(CLIENT_ID, JTI, EXPIRES_AT);

        assertEquals(CLIENT_ID, use.clientId());
        assertEquals(JTI, use.jti());
        assertEquals(EXPIRES_AT, use.expiresAt());
    }

    /**
     * Verifies that a missing or blank client identifier is rejected.
     */
    @Test
    void constructor_whenClientIdIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new ClientAssertionUse(null, JTI, EXPIRES_AT));
        assertThrows(IllegalArgumentException.class, () -> new ClientAssertionUse(" ", JTI, EXPIRES_AT));
    }

    /**
     * Verifies that a missing or blank jti is rejected.
     */
    @Test
    void constructor_whenJtiIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new ClientAssertionUse(CLIENT_ID, null, EXPIRES_AT));
        assertThrows(IllegalArgumentException.class, () -> new ClientAssertionUse(CLIENT_ID, "", EXPIRES_AT));
    }

    /**
     * Verifies that a missing expiry is rejected.
     */
    @Test
    void constructor_whenExpiryIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new ClientAssertionUse(CLIENT_ID, JTI, null));
    }

    /**
     * Verifies value semantics.
     */
    @Test
    void equalsAndHashCode_whenFieldsMatch_areEqual() {
        final var first = new ClientAssertionUse(CLIENT_ID, JTI, EXPIRES_AT);
        final var second = new ClientAssertionUse(CLIENT_ID, JTI, EXPIRES_AT);

        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
    }
}
