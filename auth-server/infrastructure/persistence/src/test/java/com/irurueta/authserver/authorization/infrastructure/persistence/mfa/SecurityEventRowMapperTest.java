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

package com.irurueta.authserver.authorization.infrastructure.persistence.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.mfa.SecurityEvent;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link SecurityEventRowMapper}.
 */
@ExtendWith(MockitoExtension.class)
class SecurityEventRowMapperTest {

    /** Instant of the event. */
    private static final Instant OCCURRED_AT = Instant.parse("2026-01-01T10:00:00Z");

    /** Username of the event. */
    private static final String USERNAME = "alice";

    /** Detail of the event. */
    private static final String DETAIL = "detail";

    /** Result set positioned on a row of {@code security_events}. */
    @Mock
    private ResultSet resultSet;

    /** Mapper under test. */
    private final SecurityEventRowMapper mapper = new SecurityEventRowMapper();

    /**
     * Verifies that a fully populated row is mapped.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenAllColumnsPresent_mapsEvent() throws SQLException {
        final var userId = UUID.randomUUID();
        when(resultSet.getString("type")).thenReturn("LOGIN_SUCCESS");
        when(resultSet.getObject("user_id", UUID.class)).thenReturn(userId);
        when(resultSet.getString("username")).thenReturn(USERNAME);
        when(resultSet.getString("detail")).thenReturn(DETAIL);
        when(resultSet.getObject("occurred_at", OffsetDateTime.class))
                .thenReturn(OCCURRED_AT.atOffset(ZoneOffset.UTC));

        assertEquals(new SecurityEvent(SecurityEventType.LOGIN_SUCCESS, userId, USERNAME, DETAIL, OCCURRED_AT),
                mapper.mapRow(resultSet, 0));
    }

    /**
     * Verifies that a row with null optional columns is mapped with null values.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenOptionalColumnsAreNull_mapsNulls() throws SQLException {
        when(resultSet.getString("type")).thenReturn("SECOND_FACTOR_FAILURE");
        when(resultSet.getObject("user_id", UUID.class)).thenReturn(null);
        when(resultSet.getObject("occurred_at", OffsetDateTime.class))
                .thenReturn(OCCURRED_AT.atOffset(ZoneOffset.UTC));

        assertEquals(new SecurityEvent(SecurityEventType.SECOND_FACTOR_FAILURE, null, null, null, OCCURRED_AT),
                mapper.mapRow(resultSet, 0));
    }
}
