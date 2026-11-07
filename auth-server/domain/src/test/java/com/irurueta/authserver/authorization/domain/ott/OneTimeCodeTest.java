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
package com.irurueta.authserver.authorization.domain.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link OneTimeCode}.
 */
class OneTimeCodeTest {

    /** Identifier used by the tests. */
    private static final UUID ID = UUID.fromString("00000000-0000-0000-0000-000000000001");

    /** User name used by the tests. */
    private static final String USERNAME = "alice";

    /** Hash used by the tests. */
    private static final String HASH = "hash";

    /** Binding used by the tests. */
    private static final String BINDING = "binding";

    /** Attempts used by the tests. */
    private static final int ATTEMPTS = 2;

    /** Creation instant used by the tests. */
    private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

    /** Expiry instant used by the tests. */
    private static final Instant EXPIRES_AT = Instant.parse("2026-01-01T00:10:00Z");

    /**
     * Verifies that valid values are kept.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var code = create(ATTEMPTS);

        assertEquals(ID, code.id());
        assertEquals(USERNAME, code.username());
        assertEquals(OttChannel.EMAIL, code.channel());
        assertEquals(OttPurpose.LOGIN, code.purpose());
        assertEquals(HASH, code.codeHash());
        assertEquals(BINDING, code.bindingId());
        assertEquals(ATTEMPTS, code.attempts());
        assertEquals(EXPIRES_AT, code.expiresAt());
        assertEquals(CREATED_AT, code.createdAt());
    }

    /**
     * Verifies that a missing id is rejected.
     */
    @Test
    void constructor_whenIdIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new OneTimeCode(null, USERNAME, OttChannel.SMS,
                OttPurpose.LOGIN, HASH, BINDING, 0, EXPIRES_AT, CREATED_AT));
    }

    /**
     * Verifies that a blank user name is rejected.
     */
    @Test
    void constructor_whenUsernameIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new OneTimeCode(ID, " ", OttChannel.SMS,
                OttPurpose.LOGIN, HASH, BINDING, 0, EXPIRES_AT, CREATED_AT));
    }

    /**
     * Verifies that a missing channel is rejected.
     */
    @Test
    void constructor_whenChannelIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new OneTimeCode(ID, USERNAME, null,
                OttPurpose.LOGIN, HASH, BINDING, 0, EXPIRES_AT, CREATED_AT));
    }

    /**
     * Verifies that a missing purpose is rejected.
     */
    @Test
    void constructor_whenPurposeIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new OneTimeCode(ID, USERNAME, OttChannel.SMS,
                null, HASH, BINDING, 0, EXPIRES_AT, CREATED_AT));
    }

    /**
     * Verifies that a blank hash is rejected.
     */
    @Test
    void constructor_whenHashIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new OneTimeCode(ID, USERNAME, OttChannel.SMS,
                OttPurpose.LOGIN, "", BINDING, 0, EXPIRES_AT, CREATED_AT));
    }

    /**
     * Verifies that a blank binding is rejected.
     */
    @Test
    void constructor_whenBindingIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new OneTimeCode(ID, USERNAME, OttChannel.SMS,
                OttPurpose.LOGIN, HASH, null, 0, EXPIRES_AT, CREATED_AT));
    }

    /**
     * Verifies that negative attempts are rejected.
     */
    @Test
    void constructor_whenAttemptsAreNegative_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> create(-1));
    }

    /**
     * Verifies that a missing expiry is rejected.
     */
    @Test
    void constructor_whenExpiresAtIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new OneTimeCode(ID, USERNAME, OttChannel.SMS,
                OttPurpose.LOGIN, HASH, BINDING, 0, null, CREATED_AT));
    }

    /**
     * Verifies that a missing creation instant is rejected.
     */
    @Test
    void constructor_whenCreatedAtIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new OneTimeCode(ID, USERNAME, OttChannel.SMS,
                OttPurpose.LOGIN, HASH, BINDING, 0, EXPIRES_AT, null));
    }

    /**
     * Verifies that an expiry before the creation is rejected.
     */
    @Test
    void constructor_whenExpiresBeforeCreation_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class, () -> new OneTimeCode(ID, USERNAME, OttChannel.SMS,
                OttPurpose.LOGIN, HASH, BINDING, 0, CREATED_AT.minusSeconds(1), CREATED_AT));
    }

    /**
     * Verifies the expiry boundary.
     */
    @Test
    void isExpiredAt_whenBeforeAtAndAfterExpiry_reflectsBoundary() {
        final var code = create(0);

        assertFalse(code.isExpiredAt(EXPIRES_AT.minusSeconds(1)));
        assertTrue(code.isExpiredAt(EXPIRES_AT));
        assertTrue(code.isExpiredAt(EXPIRES_AT.plusSeconds(1)));
    }

    /**
     * Verifies value semantics.
     */
    @Test
    void equalsAndHashCode_whenFieldsMatch_areEqual() {
        assertEquals(create(1), create(1));
        assertEquals(create(1).hashCode(), create(1).hashCode());
    }

    /**
     * Creates a valid code.
     *
     * @param attempts attempts of the code.
     * @return the code.
     */
    private static OneTimeCode create(final int attempts) {
        return new OneTimeCode(ID, USERNAME, OttChannel.EMAIL, OttPurpose.LOGIN, HASH, BINDING, attempts,
                EXPIRES_AT, CREATED_AT);
    }
}
