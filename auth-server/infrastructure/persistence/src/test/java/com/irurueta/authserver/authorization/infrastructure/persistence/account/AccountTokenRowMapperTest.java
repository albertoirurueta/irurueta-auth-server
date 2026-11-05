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

package com.irurueta.authserver.authorization.infrastructure.persistence.account;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.account.AccountToken;
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
 * Unit tests of {@link AccountTokenRowMapper}, with the result set mocked.
 */
@ExtendWith(MockitoExtension.class)
class AccountTokenRowMapperTest {

    /** Hash of the token used by the tests. */
    private static final String HASHED_TOKEN = "hashed-" + UUID.randomUUID();

    /** Purpose of the token used by the tests. */
    private static final String PURPOSE = AccountToken.PURPOSE_PASSWORD_RESET;

    /** Instant the token was used. */
    private static final Instant USED_AT = Instant.parse("2026-01-01T10:00:00Z");

    /** Instant the token expires. */
    private static final Instant EXPIRES_AT = Instant.parse("2026-01-01T11:00:00Z");

    /** Identifier of the token. */
    private final UUID id = UUID.randomUUID();

    /** Identifier of the user. */
    private final UUID userId = UUID.randomUUID();

    /** Result set positioned on a row of {@code account_tokens}. */
    @Mock
    private ResultSet resultSet;

    /** Mapper under test. */
    private final AccountTokenRowMapper mapper = new AccountTokenRowMapper();

    /**
     * Mocks the columns every test reads.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @BeforeEach
    void setUp() throws SQLException {
        when(resultSet.getObject("id", UUID.class)).thenReturn(id);
        when(resultSet.getObject("user_id", UUID.class)).thenReturn(userId);
        when(resultSet.getString("purpose")).thenReturn(PURPOSE);
        when(resultSet.getString("hashed_token")).thenReturn(HASHED_TOKEN);
        when(resultSet.getObject("expires_at", OffsetDateTime.class)).thenReturn(EXPIRES_AT.atOffset(ZoneOffset.UTC));
    }

    /**
     * Verifies that a used token is mapped with its used-at instant.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenTokenWasUsed_mapsUsedAt() throws SQLException {
        when(resultSet.getObject("used_at", OffsetDateTime.class)).thenReturn(USED_AT.atOffset(ZoneOffset.UTC));

        assertEquals(new AccountToken(id, userId, PURPOSE, HASHED_TOKEN, EXPIRES_AT, USED_AT),
                mapper.mapRow(resultSet, 0));
    }

    /**
     * Verifies that a token that was never used is mapped with a null used-at instant.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenTokenWasNeverUsed_mapsNullUsedAt() throws SQLException {
        when(resultSet.getObject("used_at", OffsetDateTime.class)).thenReturn(null);

        assertEquals(new AccountToken(id, userId, PURPOSE, HASHED_TOKEN, EXPIRES_AT, null),
                mapper.mapRow(resultSet, 0));
    }
}
