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

package com.irurueta.authserver.authorization.infrastructure.persistence.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.ott.OneTimeCode;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
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
 * Unit tests of {@link OneTimeCodeRowMapper}.
 */
@ExtendWith(MockitoExtension.class)
class OneTimeCodeRowMapperTest {

    /** Number of failed attempts of the code. */
    private static final int ATTEMPTS = 2;

    /** Instant the code was created. */
    private static final Instant CREATED_AT = Instant.parse("2026-01-01T10:00:00Z");

    /** Instant the code expires. */
    private static final Instant EXPIRES_AT = Instant.parse("2026-01-01T10:10:00Z");

    /** Identifier of the code. */
    private final UUID id = UUID.randomUUID();

    /** Result set positioned on a row of {@code ott_codes}. */
    @Mock
    private ResultSet resultSet;

    /** Mapper under test. */
    private final OneTimeCodeRowMapper mapper = new OneTimeCodeRowMapper();

    /**
     * Verifies that every column is mapped.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenRowIsComplete_mapsEveryColumn() throws SQLException {
        when(resultSet.getObject("id", UUID.class)).thenReturn(id);
        when(resultSet.getString("username")).thenReturn("user");
        when(resultSet.getString("channel")).thenReturn("SMS");
        when(resultSet.getString("purpose")).thenReturn("SECOND_FACTOR");
        when(resultSet.getString("code_hash")).thenReturn("hash");
        when(resultSet.getString("binding_id")).thenReturn("binding");
        when(resultSet.getInt("attempts")).thenReturn(ATTEMPTS);
        when(resultSet.getObject("expires_at", OffsetDateTime.class))
                .thenReturn(EXPIRES_AT.atOffset(ZoneOffset.UTC));
        when(resultSet.getObject("created_at", OffsetDateTime.class))
                .thenReturn(CREATED_AT.atOffset(ZoneOffset.UTC));

        assertEquals(new OneTimeCode(id, "user", OttChannel.SMS, OttPurpose.SECOND_FACTOR, "hash", "binding",
                ATTEMPTS, EXPIRES_AT, CREATED_AT), mapper.mapRow(resultSet, 0));
    }
}
