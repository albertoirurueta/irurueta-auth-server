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
import static org.mockito.Mockito.when;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link UserAccountRowMapper}, with the result set mocked.
 */
@ExtendWith(MockitoExtension.class)
class UserAccountRowMapperTest {

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Encoded password used by the tests; not a real credential. */
    private static final String ENCODED_PASSWORD = "{noop}encoded";

    /** E-mail address used by the tests. */
    private static final String EMAIL = "alice@example.com";

    /** Tenant used by the tests. */
    private static final String TENANT = "acme";

    /** Result set positioned on a row of {@code users} joined with {@code user_passwords}. */
    @Mock
    private ResultSet resultSet;

    /** Mapper under test. */
    private final UserAccountRowMapper mapper = new UserAccountRowMapper();

    /**
     * Verifies that every column of the row is mapped.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenRowHasEveryColumn_mapsEveryColumn() throws SQLException {
        final var id = UUID.randomUUID();
        mockRow(id, EMAIL);

        assertEquals(new UserAccountRow(id, USERNAME, ENCODED_PASSWORD, true, EMAIL, true, TENANT),
                mapper.mapRow(resultSet, 0));
    }

    /**
     * Verifies that a user without an e-mail address is mapped with a null address.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenEmailIsNull_mapsNullEmail() throws SQLException {
        final var id = UUID.randomUUID();
        mockRow(id, null);

        assertEquals(new UserAccountRow(id, USERNAME, ENCODED_PASSWORD, true, null, true, TENANT),
                mapper.mapRow(resultSet, 0));
    }

    /**
     * Mocks the columns of the row.
     *
     * @param id    identifier of the user.
     * @param email e-mail address, or {@code null}.
     * @throws SQLException never; declared by the mocked result set.
     */
    private void mockRow(final UUID id, final String email) throws SQLException {
        when(resultSet.getObject("id", UUID.class)).thenReturn(id);
        when(resultSet.getString("username")).thenReturn(USERNAME);
        when(resultSet.getString("encoded_password")).thenReturn(ENCODED_PASSWORD);
        when(resultSet.getBoolean("enabled")).thenReturn(true);
        when(resultSet.getString("email")).thenReturn(email);
        when(resultSet.getBoolean("email_verified")).thenReturn(true);
        when(resultSet.getString("tenant")).thenReturn(TENANT);
    }
}
