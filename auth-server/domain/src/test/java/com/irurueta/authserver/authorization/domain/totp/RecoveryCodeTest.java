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
package com.irurueta.authserver.authorization.domain.totp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link RecoveryCode}.
 */
class RecoveryCodeTest {

    /** Hash used by the tests. */
    private static final String HASH = "hash";

    /**
     * Verifies that valid values are kept and an unspent code is not used.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var id = UUID.randomUUID();
        final var userId = UUID.randomUUID();

        final var code = new RecoveryCode(id, userId, HASH, null);

        assertEquals(id, code.id());
        assertEquals(userId, code.userId());
        assertEquals(HASH, code.hashedCode());
        assertFalse(code.isUsed());
    }

    /**
     * Verifies that a spent code reports it.
     */
    @Test
    void isUsed_whenUsedAtIsSet_returnsTrue() {
        final var code = new RecoveryCode(UUID.randomUUID(), UUID.randomUUID(), HASH, Instant.EPOCH);

        assertTrue(code.isUsed());
    }

    /**
     * Verifies that a missing id is rejected.
     */
    @Test
    void constructor_whenIdIsNull_throwsIllegalArgumentException() {
        final var userId = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class, () -> new RecoveryCode(null, userId, HASH, null));
    }

    /**
     * Verifies that a missing user id is rejected.
     */
    @Test
    void constructor_whenUserIdIsNull_throwsIllegalArgumentException() {
        final var id = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class, () -> new RecoveryCode(id, null, HASH, null));
    }

    /**
     * Verifies that a blank hash is rejected.
     */
    @Test
    void constructor_whenHashIsBlank_throwsIllegalArgumentException() {
        final var id = UUID.randomUUID();
        final var userId = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class, () -> new RecoveryCode(id, userId, " ", null));
    }
}
