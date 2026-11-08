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
package com.irurueta.authserver.authorization.infrastructure.persistence.social;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.social.FederatedIdentity;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link FederatedIdentityRowMapper}, with the result set mocked.
 */
@ExtendWith(MockitoExtension.class)
class FederatedIdentityRowMapperTest {

    /** Subject used by the tests. */
    private static final String SUBJECT = "subject-1";

    /** E-mail address used by the tests. */
    private static final String EMAIL = "alice@example.com";

    /** Instant the identity was linked. */
    private static final Instant LINKED_AT = Instant.parse("2026-01-01T10:00:00Z");

    /** Instant of the last sign-in. */
    private static final Instant LAST_LOGIN_AT = Instant.parse("2026-02-01T10:00:00Z");

    /** Identifier of the link. */
    private final UUID id = UUID.randomUUID();

    /** Identifier of the account. */
    private final UUID userId = UUID.randomUUID();

    /** Result set positioned on a row of {@code federated_identities}. */
    @Mock
    private ResultSet resultSet;

    /** Mapper under test. */
    private final FederatedIdentityRowMapper mapper = new FederatedIdentityRowMapper();

    /**
     * Mocks the columns every test reads.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @BeforeEach
    void setUp() throws SQLException {
        when(resultSet.getString("provider")).thenReturn("github");
    }

    /**
     * Verifies that a row with an e-mail address and a last sign-in is mapped completely.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenEveryColumnIsStored_mapsEveryColumn() throws SQLException {
        stubRow(EMAIL, LAST_LOGIN_AT.atOffset(ZoneOffset.UTC));

        assertEquals(new FederatedIdentity(id, userId, IdentityProvider.GITHUB, SUBJECT, EMAIL, LINKED_AT,
                LAST_LOGIN_AT), mapper.mapRow(resultSet, 0));
    }

    /**
     * Verifies that a row without e-mail address and last sign-in is mapped with nulls.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenOptionalColumnsAreNull_mapsNulls() throws SQLException {
        stubRow(null, null);

        assertEquals(new FederatedIdentity(id, userId, IdentityProvider.GITHUB, SUBJECT, null, LINKED_AT, null),
                mapper.mapRow(resultSet, 0));
    }

    /**
     * Verifies that an unknown provider is rejected.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenProviderIsUnknown_throwsIllegalArgumentException() throws SQLException {
        when(resultSet.getString("provider")).thenReturn("myspace");

        assertThrows(IllegalArgumentException.class, () -> mapper.mapRow(resultSet, 0));
    }

    /**
     * Mocks the columns of a valid row.
     *
     * @param email       stored e-mail address, or {@code null}.
     * @param lastLoginAt stored last sign-in, or {@code null}.
     * @throws SQLException never; declared by the mocked result set.
     */
    private void stubRow(final String email, final OffsetDateTime lastLoginAt) throws SQLException {
        when(resultSet.getObject("id", UUID.class)).thenReturn(id);
        when(resultSet.getObject("user_id", UUID.class)).thenReturn(userId);
        when(resultSet.getString("subject")).thenReturn(SUBJECT);
        when(resultSet.getString("email")).thenReturn(email);
        when(resultSet.getObject("linked_at", OffsetDateTime.class)).thenReturn(LINKED_AT.atOffset(ZoneOffset.UTC));
        when(resultSet.getObject("last_login_at", OffsetDateTime.class)).thenReturn(lastLoginAt);
    }
}
