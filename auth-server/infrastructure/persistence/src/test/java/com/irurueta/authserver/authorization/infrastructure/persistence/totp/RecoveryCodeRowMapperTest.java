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

package com.irurueta.authserver.authorization.infrastructure.persistence.totp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.totp.RecoveryCode;
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
 * Unit tests of {@link RecoveryCodeRowMapper}, with the result set mocked.
 */
@ExtendWith(MockitoExtension.class)
class RecoveryCodeRowMapperTest {

    /** Hash of the code used by the tests. */
    private static final String HASHED_CODE = "hashed-" + UUID.randomUUID();

    /** Instant the code was used. */
    private static final Instant USED_AT = Instant.parse("2026-01-01T10:00:00Z");

    /** Identifier of the code. */
    private final UUID id = UUID.randomUUID();

    /** Identifier of the user. */
    private final UUID userId = UUID.randomUUID();

    /** Result set positioned on a row of {@code recovery_codes}. */
    @Mock
    private ResultSet resultSet;

    /** Mapper under test. */
    private final RecoveryCodeRowMapper mapper = new RecoveryCodeRowMapper();

    /**
     * Mocks the columns every test reads.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @BeforeEach
    void setUp() throws SQLException {
        when(resultSet.getObject("id", UUID.class)).thenReturn(id);
        when(resultSet.getObject("user_id", UUID.class)).thenReturn(userId);
        when(resultSet.getString("hashed_code")).thenReturn(HASHED_CODE);
    }

    /**
     * Verifies that a spent code is mapped with its used-at instant.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenCodeWasUsed_mapsUsedAt() throws SQLException {
        when(resultSet.getObject("used_at", OffsetDateTime.class)).thenReturn(USED_AT.atOffset(ZoneOffset.UTC));

        assertEquals(new RecoveryCode(id, userId, HASHED_CODE, USED_AT), mapper.mapRow(resultSet, 0));
    }

    /**
     * Verifies that an unused code is mapped with a null used-at instant.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenCodeWasNeverUsed_mapsNullUsedAt() throws SQLException {
        when(resultSet.getObject("used_at", OffsetDateTime.class)).thenReturn(null);

        assertEquals(new RecoveryCode(id, userId, HASHED_CODE, null), mapper.mapRow(resultSet, 0));
    }
}
