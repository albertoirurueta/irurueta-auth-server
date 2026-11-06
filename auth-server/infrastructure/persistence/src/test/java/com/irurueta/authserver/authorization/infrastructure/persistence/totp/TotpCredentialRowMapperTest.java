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

import com.irurueta.authserver.authorization.domain.totp.TotpCredential;
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
 * Unit tests of {@link TotpCredentialRowMapper}, with the result set mocked.
 */
@ExtendWith(MockitoExtension.class)
class TotpCredentialRowMapperTest {

    /** Last used step of the credential. */
    private static final long STEP = 57L;

    /** Instant the credential was created. */
    private static final Instant CREATED_AT = Instant.parse("2026-01-01T10:00:00Z");

    /** Encrypted secret of the credential. */
    private static final byte[] SECRET = {1, 2, 3};

    /** Result set positioned on a row of {@code totp_credentials}. */
    @Mock
    private ResultSet resultSet;

    /** Mapper under test. */
    private final TotpCredentialRowMapper mapper = new TotpCredentialRowMapper();

    /**
     * Verifies that every column is mapped.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenRowIsConfirmed_mapsEveryColumn() throws SQLException {
        final var userId = UUID.randomUUID();
        when(resultSet.getObject("user_id", UUID.class)).thenReturn(userId);
        when(resultSet.getBytes("encrypted_secret")).thenReturn(SECRET);
        when(resultSet.getBoolean("confirmed")).thenReturn(true);
        when(resultSet.getLong("last_used_step")).thenReturn(STEP);
        when(resultSet.getObject("created_at", OffsetDateTime.class)).thenReturn(CREATED_AT.atOffset(ZoneOffset.UTC));

        assertEquals(new TotpCredential(userId, SECRET, true, STEP, CREATED_AT), mapper.mapRow(resultSet, 0));
    }
}
