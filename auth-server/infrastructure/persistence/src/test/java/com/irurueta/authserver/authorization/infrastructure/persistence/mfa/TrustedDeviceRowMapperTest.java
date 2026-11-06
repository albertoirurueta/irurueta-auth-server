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

import com.irurueta.authserver.authorization.domain.mfa.TrustedDevice;
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
 * Unit tests of {@link TrustedDeviceRowMapper}, with the result set mocked.
 */
@ExtendWith(MockitoExtension.class)
class TrustedDeviceRowMapperTest {

    /** Hash of the token used by the tests. */
    private static final String HASHED_TOKEN = "hashed-" + UUID.randomUUID();

    /** User agent summary used by the tests. */
    private static final String USER_AGENT = "Firefox on Linux";

    /** Instant the device expires. */
    private static final Instant EXPIRES_AT = Instant.parse("2026-02-01T10:00:00Z");

    /** Instant the device was trusted. */
    private static final Instant CREATED_AT = Instant.parse("2026-01-01T10:00:00Z");

    /** Identifier of the device. */
    private final UUID id = UUID.randomUUID();

    /** Identifier of the user. */
    private final UUID userId = UUID.randomUUID();

    /** Result set positioned on a row of {@code trusted_devices}. */
    @Mock
    private ResultSet resultSet;

    /** Mapper under test. */
    private final TrustedDeviceRowMapper mapper = new TrustedDeviceRowMapper();

    /**
     * Mocks the columns every test reads.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @BeforeEach
    void setUp() throws SQLException {
        when(resultSet.getObject("id", UUID.class)).thenReturn(id);
        when(resultSet.getObject("user_id", UUID.class)).thenReturn(userId);
        when(resultSet.getString("hashed_token")).thenReturn(HASHED_TOKEN);
        when(resultSet.getObject("expires_at", OffsetDateTime.class)).thenReturn(EXPIRES_AT.atOffset(ZoneOffset.UTC));
        when(resultSet.getObject("created_at", OffsetDateTime.class)).thenReturn(CREATED_AT.atOffset(ZoneOffset.UTC));
    }

    /**
     * Verifies that a device with a user agent is mapped completely.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenUserAgentIsStored_mapsEveryColumn() throws SQLException {
        when(resultSet.getString("user_agent")).thenReturn(USER_AGENT);

        assertEquals(new TrustedDevice(id, userId, HASHED_TOKEN, USER_AGENT, EXPIRES_AT, CREATED_AT),
                mapper.mapRow(resultSet, 0));
    }

    /**
     * Verifies that a device without a user agent is mapped with a null summary.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenUserAgentIsMissing_mapsNullSummary() throws SQLException {
        when(resultSet.getString("user_agent")).thenReturn(null);

        assertEquals(new TrustedDevice(id, userId, HASHED_TOKEN, null, EXPIRES_AT, CREATED_AT),
                mapper.mapRow(resultSet, 0));
    }
}
