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
package com.irurueta.authserver.authorization.domain.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link SecurityEvent}.
 */
class SecurityEventTest {

    /** Instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /**
     * Verifies that valid values are kept.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var userId = UUID.randomUUID();

        final var event = new SecurityEvent(SecurityEventType.LOGIN_FAILURE, userId, "alice", "bad password", NOW);

        assertEquals(SecurityEventType.LOGIN_FAILURE, event.type());
        assertEquals(userId, event.userId());
        assertEquals("alice", event.username());
        assertEquals("bad password", event.detail());
        assertEquals(NOW, event.occurredAt());
    }

    /**
     * Verifies that the user, name and detail are optional.
     */
    @Test
    void constructor_whenOptionalValuesAreNull_acceptsThem() {
        final var event = new SecurityEvent(SecurityEventType.LOGIN_FAILURE, null, null, null, NOW);

        assertNull(event.userId());
        assertNull(event.username());
        assertNull(event.detail());
    }

    /**
     * Verifies that a missing type is rejected.
     */
    @Test
    void constructor_whenTypeIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new SecurityEvent(null, null, null, null, NOW));
    }

    /**
     * Verifies that a missing instant is rejected.
     */
    @Test
    void constructor_whenInstantIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new SecurityEvent(SecurityEventType.LOGIN_SUCCESS, null, null, null, null));
    }

    /**
     * Verifies that a blank username is rejected.
     */
    @Test
    void constructor_whenUsernameIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new SecurityEvent(SecurityEventType.LOGIN_SUCCESS, null, " ", null, NOW));
    }

    /**
     * Verifies that a blank detail is rejected.
     */
    @Test
    void constructor_whenDetailIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new SecurityEvent(SecurityEventType.LOGIN_SUCCESS, null, null, "", NOW));
    }
}
