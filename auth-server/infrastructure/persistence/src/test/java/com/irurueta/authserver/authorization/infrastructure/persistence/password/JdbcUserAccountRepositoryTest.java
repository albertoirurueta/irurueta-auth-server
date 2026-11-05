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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.sql.ResultSet;
import java.sql.SQLException;
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

    /** JDBC client that runs the queries. */
    @Mock(answer = Answers.RETURNS_DEEP_STUBS)
    private JdbcClient client;

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
     * Verifies that the row and the authorities of an existing user are mapped to an account.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void findByUsername_whenUserExists_returnsAccount() throws SQLException {
        final var id = UUID.randomUUID();
        final var resultSet = mock(ResultSet.class);
        when(resultSet.getObject("id", UUID.class)).thenReturn(id);
        when(resultSet.getString("username")).thenReturn(USERNAME);
        when(resultSet.getString("encoded_password")).thenReturn(ENCODED_PASSWORD);
        when(resultSet.getBoolean("enabled")).thenReturn(false);
        final var captor = ArgumentCaptor.<RowMapper<Object>>captor();
        final var spec = client.sql(any(String.class)).param(any());
        when(spec.query(captor.capture()).optional())
                .thenAnswer(invocation -> Optional.of(captor.getValue().mapRow(resultSet, 0)));
        when(spec.query(String.class).list()).thenReturn(List.of(ROLE_USER));

        final var account = repository.findByUsername(USERNAME).orElseThrow();

        assertEquals(id, account.id());
        assertEquals(USERNAME, account.username());
        assertEquals(ENCODED_PASSWORD, account.encodedPassword());
        assertFalse(account.enabled());
        assertEquals(List.of(ROLE_USER), account.authorities());
    }
}
