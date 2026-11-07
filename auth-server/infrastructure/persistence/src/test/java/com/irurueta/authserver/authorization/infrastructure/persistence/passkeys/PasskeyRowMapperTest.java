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

package com.irurueta.authserver.authorization.infrastructure.persistence.passkeys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.passkeys.Passkey;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link PasskeyRowMapper}, with the result set mocked.
 */
@ExtendWith(MockitoExtension.class)
class PasskeyRowMapperTest {

    /** Signature counter of the credential. */
    private static final long COUNTER = 7L;

    /** Instant the credential was created. */
    private static final Instant CREATED = Instant.parse("2026-01-01T10:00:00Z");

    /** Instant the credential was last used. */
    private static final Instant LAST_USED = Instant.parse("2026-02-01T10:00:00Z");

    /** Result set positioned on a row of {@code user_credentials}. */
    @Mock
    private ResultSet resultSet;

    /** Mapper under test. */
    private final PasskeyRowMapper mapper = new PasskeyRowMapper();

    /**
     * Verifies that every column is mapped.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenRowIsComplete_mapsEveryColumn() throws SQLException {
        stubIdentity();
        when(resultSet.getTimestamp("created")).thenReturn(Timestamp.from(CREATED));
        when(resultSet.getTimestamp("last_used")).thenReturn(Timestamp.from(LAST_USED));
        when(resultSet.getLong("signature_count")).thenReturn(COUNTER);
        when(resultSet.getBoolean("backup_eligible")).thenReturn(true);
        when(resultSet.getBoolean("backup_state")).thenReturn(false);

        final var passkey = mapper.mapRow(resultSet, 0);

        assertEquals(new Passkey("cred", "user", "Laptop", CREATED, LAST_USED, COUNTER, true, false), passkey);
        assertTrue(passkey.backupEligible());
        assertFalse(passkey.backedUp());
    }

    /**
     * Verifies that a credential never used has no last use, and one without a creation time gets the epoch.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void mapRow_whenTimestampsAreNull_usesEpochAndNoLastUse() throws SQLException {
        stubIdentity();

        final var passkey = mapper.mapRow(resultSet, 0);

        assertEquals(Instant.EPOCH, passkey.createdAt());
        assertNull(passkey.lastUsedAt());
    }

    /**
     * Stubs the identifying columns.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    private void stubIdentity() throws SQLException {
        when(resultSet.getString("credential_id")).thenReturn("cred");
        when(resultSet.getString("user_entity_user_id")).thenReturn("user");
        when(resultSet.getString("label")).thenReturn("Laptop");
    }
}
