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

package com.irurueta.authserver.authorization.infrastructure.persistence.passkeys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.passkeys.Passkey;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Unit tests of {@link JdbcPasskeyRepository}, with the JDBC client mocked. The statements themselves run against
 * PostgreSQL in {@link JdbcPasskeyRepositoryIT}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcPasskeyRepositoryTest {

    /** Identifier of the credential. */
    private static final String ID = "cred";

    /** User handle of the owner. */
    private static final String USER = "user";

    /** JDBC client that runs the statements. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient client;

    /** Maps a row to a passkey; mocked so the tests control the mapped passkeys. */
    @Mock
    private PasskeyRowMapper passkeyRowMapper;

    /** Repository under test. */
    @InjectMocks
    private JdbcPasskeyRepository repository;

    /**
     * Verifies that the user handle the query returns is passed through.
     */
    @Test
    void findUserIdByUsername_whenAccountHasAnEntity_returnsHandle() {
        when(client.sql(any(String.class)).param("alice").query(String.class).optional())
                .thenReturn(Optional.of(USER));

        assertEquals(USER, repository.findUserIdByUsername("alice").orElseThrow());
    }

    /**
     * Verifies that the passkeys of a user are returned as mapped.
     */
    @Test
    void findByUserId_whenUserHasPasskeys_returnsThem() {
        final var passkeys = List.of(passkey());
        when(client.sql(any(String.class)).param(USER).query(passkeyRowMapper).list()).thenReturn(passkeys);

        assertSame(passkeys, repository.findByUserId(USER));
    }

    /**
     * Verifies that one passkey is returned as mapped.
     */
    @Test
    void findByIdAndUserId_whenRowMatches_returnsPasskey() {
        final var passkey = passkey();
        when(client.sql(any(String.class)).params(ID, USER).query(passkeyRowMapper).optional())
                .thenReturn(Optional.of(passkey));

        assertSame(passkey, repository.findByIdAndUserId(ID, USER).orElseThrow());
    }

    /**
     * Verifies that renaming reports whether a row changed.
     */
    @Test
    void rename_whenRowChanges_returnsTrue() {
        when(client.sql(any(String.class)).params("Phone", ID, USER).update()).thenReturn(1);

        assertTrue(repository.rename(ID, USER, "Phone"));
    }

    /**
     * Verifies that renaming a passkey that is not there returns {@code false}.
     */
    @Test
    void rename_whenNoRowChanges_returnsFalse() {
        when(client.sql(any(String.class)).params("Phone", ID, USER).update()).thenReturn(0);

        assertFalse(repository.rename(ID, USER, "Phone"));
    }

    /**
     * Verifies that deleting reports whether a row was removed.
     */
    @Test
    void delete_whenRowIsRemoved_returnsTrue() {
        when(client.sql(any(String.class)).params(ID, USER).update()).thenReturn(1);

        assertTrue(repository.delete(ID, USER));
    }

    /**
     * Verifies that deleting a passkey that is not there returns {@code false}.
     */
    @Test
    void delete_whenNoRowIsRemoved_returnsFalse() {
        when(client.sql(any(String.class)).params(ID, USER).update()).thenReturn(0);

        assertFalse(repository.delete(ID, USER));
    }

    /**
     * Verifies that the answer of the existence query is passed through.
     */
    @Test
    void existsForAccount_whenQueryAnswersTrue_returnsTrue() {
        final var accountId = UUID.randomUUID();
        when(client.sql(any(String.class)).param(accountId).query(Boolean.class).single()).thenReturn(true);

        assertTrue(repository.existsForAccount(accountId));
    }

    /**
     * Verifies that a {@code false} answer of the existence query is passed through.
     */
    @Test
    void existsForAccount_whenQueryAnswersFalse_returnsFalse() {
        final var accountId = UUID.randomUUID();
        when(client.sql(any(String.class)).param(accountId).query(Boolean.class).single()).thenReturn(false);

        assertFalse(repository.existsForAccount(accountId));
    }

    /**
     * Builds a passkey.
     *
     * @return the passkey.
     */
    private static Passkey passkey() {
        return new Passkey(ID, USER, "Laptop", Instant.EPOCH, null, 0L, false, false);
    }
}
