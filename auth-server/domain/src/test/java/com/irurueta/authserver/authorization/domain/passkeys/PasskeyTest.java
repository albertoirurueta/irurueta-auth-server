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
package com.irurueta.authserver.authorization.domain.passkeys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link Passkey}.
 */
class PasskeyTest {

    /** Credential identifier used by the tests. */
    private static final String ID = "credential-id";

    /** User handle used by the tests. */
    private static final String USER_ID = "user-handle";

    /** Label used by the tests. */
    private static final String LABEL = "Laptop";

    /** Creation instant used by the tests. */
    private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

    /** Last use instant used by the tests. */
    private static final Instant LAST_USED_AT = Instant.parse("2026-02-01T00:00:00Z");

    /** Signature counter used by the tests. */
    private static final long COUNT = 7L;

    /**
     * Verifies that valid values are kept.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var passkey = new Passkey(ID, USER_ID, LABEL, CREATED_AT, LAST_USED_AT, COUNT, true, false);

        assertEquals(ID, passkey.id());
        assertEquals(USER_ID, passkey.userId());
        assertEquals(LABEL, passkey.label());
        assertEquals(CREATED_AT, passkey.createdAt());
        assertEquals(LAST_USED_AT, passkey.lastUsedAt());
        assertEquals(COUNT, passkey.signatureCount());
        assertTrue(passkey.backupEligible());
        assertFalse(passkey.backedUp());
    }

    /**
     * Verifies that a passkey that was never used has no last use instant.
     */
    @Test
    void constructor_whenLastUsedIsNull_acceptsIt() {
        final var passkey = new Passkey(ID, USER_ID, LABEL, CREATED_AT, null, 0L, false, false);

        assertNull(passkey.lastUsedAt());
    }

    /**
     * Verifies that a blank id is rejected.
     */
    @Test
    void constructor_whenIdIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new Passkey(" ", USER_ID, LABEL, CREATED_AT, null, 0L, false, false));
    }

    /**
     * Verifies that a missing user id is rejected.
     */
    @Test
    void constructor_whenUserIdIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new Passkey(ID, null, LABEL, CREATED_AT, null, 0L, false, false));
    }

    /**
     * Verifies that a blank label is rejected.
     */
    @Test
    void constructor_whenLabelIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new Passkey(ID, USER_ID, " ", CREATED_AT, null, 0L, false, false));
    }

    /**
     * Verifies that a missing creation instant is rejected.
     */
    @Test
    void constructor_whenCreatedAtIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new Passkey(ID, USER_ID, LABEL, null, null, 0L, false, false));
    }

    /**
     * Verifies that a negative signature counter is rejected.
     */
    @Test
    void constructor_whenSignatureCountIsNegative_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new Passkey(ID, USER_ID, LABEL, CREATED_AT, null, -1L, false, false));
    }

    /**
     * Verifies that passkeys with the same values are equal.
     */
    @Test
    void equalsAndHashCode_whenFieldsMatch_areEqual() {
        final var first = new Passkey(ID, USER_ID, LABEL, CREATED_AT, LAST_USED_AT, COUNT, true, true);
        final var second = new Passkey(ID, USER_ID, LABEL, CREATED_AT, LAST_USED_AT, COUNT, true, true);

        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
    }
}
