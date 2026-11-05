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

package com.irurueta.authserver.authorization.domain.password;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link UserAccount}.
 */
class UserAccountTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Encoded password used by the tests; not a real credential. */
    private static final String ENCODED_PASSWORD = "{noop}encoded";

    /** Authority used by the tests. */
    private static final String ROLE_USER = "ROLE_USER";

    /** Another authority used by the tests. */
    private static final String ROLE_ADMIN = "ROLE_ADMIN";

    /**
     * Verifies that valid values are kept as they are.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var id = UUID.randomUUID();

        final var account = new UserAccount(id, USERNAME, ENCODED_PASSWORD, true, List.of(ROLE_USER));

        assertEquals(id, account.id());
        assertEquals(USERNAME, account.username());
        assertEquals(ENCODED_PASSWORD, account.encodedPassword());
        assertTrue(account.enabled());
        assertEquals(List.of(ROLE_USER), account.authorities());
    }

    /**
     * Verifies that a null id is rejected.
     */
    @Test
    void constructor_whenIdIsNull_throwsIllegalArgumentException() {
        final var authorities = List.<String>of();

        assertThrows(IllegalArgumentException.class,
                () -> new UserAccount(null, USERNAME, ENCODED_PASSWORD, true, authorities));
    }

    /**
     * Verifies that a null username is rejected.
     */
    @Test
    void constructor_whenUsernameIsNull_throwsIllegalArgumentException() {
        final var id = UUID.randomUUID();
        final var authorities = List.<String>of();

        assertThrows(IllegalArgumentException.class,
                () -> new UserAccount(id, null, ENCODED_PASSWORD, true, authorities));
    }

    /**
     * Verifies that a blank username is rejected.
     */
    @Test
    void constructor_whenUsernameIsBlank_throwsIllegalArgumentException() {
        final var id = UUID.randomUUID();
        final var authorities = List.<String>of();

        assertThrows(IllegalArgumentException.class,
                () -> new UserAccount(id, " ", ENCODED_PASSWORD, true, authorities));
    }

    /**
     * Verifies that a null encoded password is rejected.
     */
    @Test
    void constructor_whenEncodedPasswordIsNull_throwsIllegalArgumentException() {
        final var id = UUID.randomUUID();
        final var authorities = List.<String>of();

        assertThrows(IllegalArgumentException.class,
                () -> new UserAccount(id, USERNAME, null, true, authorities));
    }

    /**
     * Verifies that a blank encoded password is rejected.
     */
    @Test
    void constructor_whenEncodedPasswordIsBlank_throwsIllegalArgumentException() {
        final var id = UUID.randomUUID();
        final var authorities = List.<String>of();

        assertThrows(IllegalArgumentException.class,
                () -> new UserAccount(id, USERNAME, "", true, authorities));
    }

    /**
     * Verifies that null authorities are rejected.
     */
    @Test
    void constructor_whenAuthoritiesAreNull_throwsIllegalArgumentException() {
        final var id = UUID.randomUUID();

        assertThrows(IllegalArgumentException.class,
                () -> new UserAccount(id, USERNAME, ENCODED_PASSWORD, true, null));
    }

    /**
     * Verifies that a null authority is rejected.
     */
    @Test
    void constructor_whenAnAuthorityIsNull_throwsIllegalArgumentException() {
        final var id = UUID.randomUUID();
        final var authorities = new ArrayList<String>();
        authorities.add(null);

        assertThrows(IllegalArgumentException.class,
                () -> new UserAccount(id, USERNAME, ENCODED_PASSWORD, true, authorities));
    }

    /**
     * Verifies that changing the list given to the constructor does not change the account.
     */
    @Test
    void constructor_whenSourceListChanges_doesNotChangeAccount() {
        final var source = new ArrayList<>(List.of(ROLE_USER));
        final var account = new UserAccount(UUID.randomUUID(), USERNAME, ENCODED_PASSWORD, true, source);

        source.add(ROLE_ADMIN);

        assertEquals(List.of(ROLE_USER), account.authorities());
    }

    /**
     * Verifies that the authorities of an account cannot be modified.
     */
    @Test
    void authorities_whenModified_throwsUnsupportedOperationException() {
        final var account = new UserAccount(UUID.randomUUID(), USERNAME, ENCODED_PASSWORD, true,
                List.of(ROLE_USER));
        final var authorities = account.authorities();

        assertThrows(UnsupportedOperationException.class, () -> authorities.add(ROLE_ADMIN));
    }

    /**
     * Verifies that accounts with the same fields are equal and accounts with different fields are not.
     */
    @Test
    void equalsAndHashCode_whenFieldsMatch_areEqual() {
        final var id = UUID.randomUUID();
        final var first = new UserAccount(id, USERNAME, ENCODED_PASSWORD, true, List.of(ROLE_USER));
        final var same = new UserAccount(id, USERNAME, ENCODED_PASSWORD, true, List.of(ROLE_USER));
        final var disabled = new UserAccount(id, USERNAME, ENCODED_PASSWORD, false, List.of(ROLE_USER));

        assertEquals(first, same);
        assertEquals(first.hashCode(), same.hashCode());
        assertNotEquals(first, disabled);
        assertFalse(disabled.enabled());
    }
}
