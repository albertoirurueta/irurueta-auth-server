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

package com.irurueta.authserver.authorization.domain.account;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link AccountToken}.
 */
class AccountTokenTest {

    /** Hash used by the tests. */
    private static final String HASH = "hash";

    /** Expiry used by the tests. */
    private static final Instant EXPIRES_AT = Instant.parse("2026-01-01T00:00:00Z");

    /**
     * Verifies that valid values are kept.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var id = UUID.randomUUID();
        final var userId = UUID.randomUUID();

        final var token = new AccountToken(id, userId, AccountToken.PURPOSE_PASSWORD_RESET, HASH, EXPIRES_AT, null);

        assertEquals(id, token.id());
        assertEquals(userId, token.userId());
        assertEquals(AccountToken.PURPOSE_PASSWORD_RESET, token.purpose());
        assertEquals(HASH, token.hashedToken());
        assertEquals(EXPIRES_AT, token.expiresAt());
        assertNull(token.usedAt());
    }

    /**
     * Verifies that a missing id is rejected.
     */
    @Test
    void constructor_whenIdIsNull_throwsIllegalArgumentException() {
        final var userId = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class,
                () -> new AccountToken(null, userId, AccountToken.PURPOSE_PASSWORD_RESET, HASH, EXPIRES_AT, null));
    }

    /**
     * Verifies that a missing user id is rejected.
     */
    @Test
    void constructor_whenUserIdIsNull_throwsIllegalArgumentException() {
        final var id = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class,
                () -> new AccountToken(id, null, AccountToken.PURPOSE_PASSWORD_RESET, HASH, EXPIRES_AT, null));
    }

    /**
     * Verifies that a blank purpose is rejected.
     */
    @Test
    void constructor_whenPurposeIsBlank_throwsIllegalArgumentException() {
        final var id = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class,
                () -> new AccountToken(id, id, " ", HASH, EXPIRES_AT, null));
    }

    /**
     * Verifies that a blank hash is rejected.
     */
    @Test
    void constructor_whenHashIsBlank_throwsIllegalArgumentException() {
        final var id = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class,
                () -> new AccountToken(id, id, AccountToken.PURPOSE_PASSWORD_RESET, null, EXPIRES_AT, null));
    }

    /**
     * Verifies that a missing expiry is rejected.
     */
    @Test
    void constructor_whenExpiryIsNull_throwsIllegalArgumentException() {
        final var id = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class,
                () -> new AccountToken(id, id, AccountToken.PURPOSE_PASSWORD_RESET, HASH, null, null));
    }
}
