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

package com.irurueta.authserver.authorization.infrastructure.persistence.password;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.password.UserAccount;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Unit tests of {@link JdbcUserAccountRepository}, with the JDBC client mocked. The queries themselves run
 * against PostgreSQL in {@link JdbcUserAccountRepositoryIT}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcUserAccountRepositoryTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Encoded password used by the tests; not a real credential. */
    private static final String ENCODED_PASSWORD = "{noop}encoded";

    /** Authority used by the tests. */
    private static final String ROLE_USER = "ROLE_USER";

    /** E-mail address used by the tests. */
    private static final String EMAIL = "alice@example.com";

    /** Tenant used by the tests. */
    private static final String TENANT = "acme";

    /** Number of statements saving an account with two authorities runs. */
    private static final int FIVE = 5;

    /** JDBC client that runs the queries. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient client;

    /** Maps a user row; mocked so the tests control the row. */
    @Mock
    private UserAccountRowMapper userAccountRowMapper;

    /** Repository under test. */
    @InjectMocks
    private JdbcUserAccountRepository repository;

    /**
     * Verifies that an empty result is returned when no user matches.
     */
    @Test
    void findByUsername_whenUserIsMissing_returnsEmpty() {
        when(client.sql(any(String.class)).param(any())
                .query(ArgumentMatchers.<RowMapper<Object>>any()).optional())
                .thenReturn(Optional.empty());

        assertTrue(repository.findByUsername(USERNAME).isEmpty());
    }

    /**
     * Verifies that the row of an existing user is completed with its authorities.
     */
    @Test
    void findByUsername_whenUserExists_returnsAccountWithAuthorities() {
        final var id = UUID.randomUUID();
        final var row = new UserAccountRow(id, USERNAME, ENCODED_PASSWORD, false, null, false,
                UserAccount.DEFAULT_TENANT);
        final var spec = client.sql(any(String.class)).param(any());
        when(spec.query(userAccountRowMapper).optional()).thenReturn(Optional.of(row));
        when(spec.query(String.class).list()).thenReturn(List.of(ROLE_USER));

        final var account = repository.findByUsername(USERNAME).orElseThrow();

        assertEquals(row.toUserAccount(List.of(ROLE_USER)), account);
    }

    /**
     * Verifies that an empty result is returned when no user has the identifier.
     */
    @Test
    void findById_whenUserIsMissing_returnsEmpty() {
        when(client.sql(any(String.class)).param(any())
                .query(ArgumentMatchers.<RowMapper<Object>>any()).optional())
                .thenReturn(Optional.empty());

        assertTrue(repository.findById(UUID.randomUUID()).isEmpty());
    }

    /**
     * Verifies that an existing username is reported as existing.
     */
    @Test
    void existsByUsername_whenUserExists_returnsTrue() {
        when(client.sql(any(String.class)).param(any()).query(Integer.class).single()).thenReturn(1);

        assertTrue(repository.existsByUsername(USERNAME));
    }

    /**
     * Verifies that an unknown username is reported as missing.
     */
    @Test
    void existsByUsername_whenUserIsMissing_returnsFalse() {
        when(client.sql(any(String.class)).param(any()).query(Integer.class).single()).thenReturn(0);

        assertFalse(repository.existsByUsername(USERNAME));
    }

    /**
     * Verifies that the new hash is written with the user id.
     */
    @Test
    void updatePassword_whenCalled_updatesTheRow() {
        final var id = UUID.randomUUID();

        repository.updatePassword(id, ENCODED_PASSWORD);

        verify(client.sql(any(String.class)).params(ENCODED_PASSWORD, id)).update();
    }

    /**
     * Verifies that an empty result is returned when no user has the e-mail address.
     */
    @Test
    void findByEmail_whenUserIsMissing_returnsEmpty() {
        when(client.sql(any(String.class)).param(any())
                .query(ArgumentMatchers.<RowMapper<Object>>any()).optional())
                .thenReturn(Optional.empty());

        assertTrue(repository.findByEmail(EMAIL).isEmpty());
    }

    /**
     * Verifies that a user found by e-mail address keeps the e-mail columns of its row.
     */
    @Test
    void findByEmail_whenUserExists_returnsAccountWithEmailColumns() {
        final var row = new UserAccountRow(UUID.randomUUID(), USERNAME, ENCODED_PASSWORD, true, EMAIL, true, TENANT);
        final var spec = client.sql(any(String.class)).param(any());
        when(spec.query(userAccountRowMapper).optional()).thenReturn(Optional.of(row));
        when(spec.query(String.class).list()).thenReturn(List.of());

        final var account = repository.findByEmail(EMAIL).orElseThrow();

        assertEquals(EMAIL, account.email());
        assertTrue(account.emailVerified());
        assertEquals(TENANT, account.tenant());
    }

    /**
     * Verifies that saving writes the user, its password and one row per authority.
     */
    @Test
    void save_whenAccountHasTwoAuthorities_runsFiveStatements() {
        final var account = new UserAccount(UUID.randomUUID(), USERNAME, ENCODED_PASSWORD, true,
                List.of(ROLE_USER, "ROLE_ADMIN"), EMAIL, false, TENANT);

        repository.save(account);

        final var sql = ArgumentCaptor.<String>captor();
        verify(client, times(FIVE)).sql(sql.capture());
        final var statements = sql.getAllValues();
        assertTrue(statements.get(0).contains("INSERT INTO users"));
        assertTrue(statements.get(1).contains("user_passwords"));
        assertTrue(statements.get(2).contains("DELETE FROM user_authorities"));
        assertTrue(statements.getLast().contains("INSERT INTO user_authorities"));
    }

    /**
     * Verifies that the e-mail is marked as verified for the user, and that the change is reported.
     */
    @Test
    void markEmailVerified_whenRowChanges_returnsTrue() {
        final var id = UUID.randomUUID();
        when(client.sql(any(String.class)).param(id).update()).thenReturn(1);

        assertTrue(repository.markEmailVerified(id));
    }

    /**
     * Verifies that an already verified (or missing) user is reported as unchanged.
     */
    @Test
    void markEmailVerified_whenNoRowChanges_returnsFalse() {
        final var id = UUID.randomUUID();
        when(client.sql(any(String.class)).param(id).update()).thenReturn(0);

        assertFalse(repository.markEmailVerified(id));
    }
}
