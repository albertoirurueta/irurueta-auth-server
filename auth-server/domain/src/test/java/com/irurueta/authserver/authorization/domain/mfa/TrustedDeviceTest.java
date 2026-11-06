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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link TrustedDevice}.
 */
class TrustedDeviceTest {

    /** Hash used by the tests. */
    private static final String HASH = "hash";

    /** Creation instant used by the tests. */
    private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

    /** Expiry used by the tests. */
    private static final Instant EXPIRES_AT = Instant.parse("2026-01-31T00:00:00Z");

    /**
     * Verifies that valid values are kept.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var id = UUID.randomUUID();
        final var userId = UUID.randomUUID();

        final var device = new TrustedDevice(id, userId, HASH, "Firefox on Linux", EXPIRES_AT, CREATED_AT);

        assertEquals(id, device.id());
        assertEquals(userId, device.userId());
        assertEquals(HASH, device.hashedToken());
        assertEquals("Firefox on Linux", device.userAgentSummary());
        assertEquals(EXPIRES_AT, device.expiresAt());
        assertEquals(CREATED_AT, device.createdAt());
    }

    /**
     * Verifies that the summary is optional.
     */
    @Test
    void constructor_whenSummaryIsNull_acceptsIt() {
        final var device = new TrustedDevice(UUID.randomUUID(), UUID.randomUUID(), HASH, null, EXPIRES_AT, CREATED_AT);

        assertNull(device.userAgentSummary());
    }

    /**
     * Verifies that a blank summary is rejected.
     */
    @Test
    void constructor_whenSummaryIsBlank_throwsIllegalArgumentException() {
        final var id = UUID.randomUUID();
        final var userId = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class,
                () -> new TrustedDevice(id, userId, HASH, " ", EXPIRES_AT, CREATED_AT));
    }

    /**
     * Verifies that a missing id is rejected.
     */
    @Test
    void constructor_whenIdIsNull_throwsIllegalArgumentException() {
        final var userId = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class,
                () -> new TrustedDevice(null, userId, HASH, null, EXPIRES_AT, CREATED_AT));
    }

    /**
     * Verifies that a missing user id is rejected.
     */
    @Test
    void constructor_whenUserIdIsNull_throwsIllegalArgumentException() {
        final var id = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class,
                () -> new TrustedDevice(id, null, HASH, null, EXPIRES_AT, CREATED_AT));
    }

    /**
     * Verifies that a blank hash is rejected.
     */
    @Test
    void constructor_whenHashIsBlank_throwsIllegalArgumentException() {
        final var id = UUID.randomUUID();
        final var userId = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class,
                () -> new TrustedDevice(id, userId, " ", null, EXPIRES_AT, CREATED_AT));
    }

    /**
     * Verifies that a missing expiry is rejected.
     */
    @Test
    void constructor_whenExpiryIsNull_throwsIllegalArgumentException() {
        final var id = UUID.randomUUID();
        final var userId = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class,
                () -> new TrustedDevice(id, userId, HASH, null, null, CREATED_AT));
    }

    /**
     * Verifies that a missing creation instant is rejected.
     */
    @Test
    void constructor_whenCreationIsNull_throwsIllegalArgumentException() {
        final var id = UUID.randomUUID();
        final var userId = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class,
                () -> new TrustedDevice(id, userId, HASH, null, EXPIRES_AT, null));
    }

    /**
     * Verifies that a device is trusted before its expiry.
     */
    @Test
    void isExpired_whenBeforeExpiry_returnsFalse() {
        final var device = new TrustedDevice(UUID.randomUUID(), UUID.randomUUID(), HASH, null, EXPIRES_AT, CREATED_AT);

        assertFalse(device.isExpired(EXPIRES_AT.minusSeconds(1)));
    }

    /**
     * Verifies that a device is no longer trusted at its expiry.
     */
    @Test
    void isExpired_whenAtExpiry_returnsTrue() {
        final var device = new TrustedDevice(UUID.randomUUID(), UUID.randomUUID(), HASH, null, EXPIRES_AT, CREATED_AT);

        assertTrue(device.isExpired(EXPIRES_AT));
    }
}
