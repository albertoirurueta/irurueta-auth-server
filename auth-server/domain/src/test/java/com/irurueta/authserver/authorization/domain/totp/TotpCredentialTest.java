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

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link TotpCredential}.
 */
class TotpCredentialTest {

    /** Creation instant used by the tests. */
    private static final Instant CREATED_AT = Instant.parse("2026-01-01T00:00:00Z");

    /** Secret bytes used by the tests. */
    private static final byte[] SECRET = {1, 2, 3};

    /** Byte that differs from every byte of {@link #SECRET}. */
    private static final byte OTHER_BYTE = 9;

    /**
     * Verifies that valid values are kept.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var userId = UUID.randomUUID();

        final var credential = new TotpCredential(userId, SECRET, true, 2L, CREATED_AT);

        assertEquals(userId, credential.userId());
        assertArrayEquals(SECRET, credential.encryptedSecret());
        assertTrue(credential.confirmed());
        assertEquals(2L, credential.lastUsedStep());
        assertEquals(CREATED_AT, credential.createdAt());
    }

    /**
     * Verifies that the secret is copied on the way in and on the way out.
     */
    @Test
    void constructor_whenSecretIsModifiedAfterwards_keepsOriginal() {
        final var secret = SECRET.clone();
        final var credential =
                new TotpCredential(UUID.randomUUID(), secret, false, TotpCredential.NEVER_USED, CREATED_AT);

        secret[0] = OTHER_BYTE;
        credential.encryptedSecret()[1] = OTHER_BYTE;

        assertArrayEquals(SECRET, credential.encryptedSecret());
    }

    /**
     * Verifies that a missing user is rejected.
     */
    @Test
    void constructor_whenUserIdIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new TotpCredential(null, SECRET, false, TotpCredential.NEVER_USED, CREATED_AT));
    }

    /**
     * Verifies that a missing creation instant is rejected.
     */
    @Test
    void constructor_whenCreationIsNull_throwsIllegalArgumentException() {
        final var userId = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class,
                () -> new TotpCredential(userId, SECRET, false, TotpCredential.NEVER_USED, null));
    }

    /**
     * Verifies that a missing secret is rejected.
     */
    @Test
    void constructor_whenSecretIsNull_throwsIllegalArgumentException() {
        final var userId = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class,
                () -> new TotpCredential(userId, null, false, TotpCredential.NEVER_USED, CREATED_AT));
    }

    /**
     * Verifies that an empty secret is rejected.
     */
    @Test
    void constructor_whenSecretIsEmpty_throwsIllegalArgumentException() {
        final var userId = UUID.randomUUID();
        final var empty = new byte[0];

        assertThrows(IllegalArgumentException.class,
                () -> new TotpCredential(userId, empty, false, TotpCredential.NEVER_USED, CREATED_AT));
    }

    /**
     * Verifies that a step below the never-used marker is rejected.
     */
    @Test
    void constructor_whenStepIsBelowNeverUsed_throwsIllegalArgumentException() {
        final var userId = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class,
                () -> new TotpCredential(userId, SECRET, false, TotpCredential.NEVER_USED - 1, CREATED_AT));
    }

    /**
     * Verifies that credentials with the same values are equal, comparing the secret by content.
     */
    @Test
    void equalsAndHashCode_whenFieldsMatch_areEqual() {
        final var userId = UUID.randomUUID();
        final var first = new TotpCredential(userId, SECRET, true, 1L, CREATED_AT);
        final var second = new TotpCredential(userId, SECRET.clone(), true, 1L, CREATED_AT);

        assertEquals(first, second);
        assertEquals(first.hashCode(), second.hashCode());
    }

    /**
     * Verifies that credentials differing in any value are not equal.
     */
    @Test
    void equalsAndHashCode_whenFieldsDiffer_areNotEqual() {
        final var userId = UUID.randomUUID();
        final var base = new TotpCredential(userId, SECRET, true, 1L, CREATED_AT);

        assertNotEquals(base, new TotpCredential(UUID.randomUUID(), SECRET, true, 1L, CREATED_AT));
        assertNotEquals(base, new TotpCredential(userId, new byte[] {OTHER_BYTE}, true, 1L, CREATED_AT));
        assertNotEquals(base, new TotpCredential(userId, SECRET, false, 1L, CREATED_AT));
        assertNotEquals(base, new TotpCredential(userId, SECRET, true, 2L, CREATED_AT));
        assertNotEquals(base, new TotpCredential(userId, SECRET, true, 1L, CREATED_AT.plusSeconds(1)));
        assertNotEquals(base, "other");
    }

    /**
     * Verifies that the description never includes the secret.
     */
    @Test
    void toString_whenCalled_doesNotIncludeSecret() {
        final var credential = new TotpCredential(UUID.randomUUID(), SECRET, true, 1L, CREATED_AT);

        assertFalse(credential.toString().contains("encryptedSecret"));
        assertTrue(credential.toString().contains("confirmed=true"));
    }
}
