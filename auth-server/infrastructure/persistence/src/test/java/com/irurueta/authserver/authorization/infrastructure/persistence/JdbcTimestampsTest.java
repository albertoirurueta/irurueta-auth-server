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

package com.irurueta.authserver.authorization.infrastructure.persistence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.when;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link JdbcTimestamps}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcTimestampsTest {

    /** Instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    /** Column read by the tests. */
    private static final String COLUMN = "created_at";

    /** Result set positioned on a row. */
    @Mock
    private ResultSet resultSet;

    /**
     * Verifies that an instant is bound as the same instant in UTC.
     */
    @Test
    void toTimestamp_whenInstantIsGiven_returnsUtcDateTime() {
        final var timestamp = JdbcTimestamps.toTimestamp(NOW);

        assertEquals(ZoneOffset.UTC, timestamp.getOffset());
        assertEquals(NOW, timestamp.toInstant());
    }

    /**
     * Verifies that a missing instant is bound as SQL {@code NULL}.
     */
    @Test
    void toTimestamp_whenInstantIsNull_returnsNull() {
        assertNull(JdbcTimestamps.toTimestamp(null));
    }

    /**
     * Verifies that a column value is read as its instant, whatever its offset.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void readInstant_whenColumnHasValue_returnsInstant() throws SQLException {
        when(resultSet.getObject(COLUMN, OffsetDateTime.class))
                .thenReturn(NOW.atOffset(ZoneOffset.ofHours(2)));

        assertEquals(NOW, JdbcTimestamps.readInstant(resultSet, COLUMN));
    }

    /**
     * Verifies that a null column is read as {@code null}.
     *
     * @throws SQLException never; declared by the mocked result set.
     */
    @Test
    void readInstant_whenColumnIsNull_returnsNull() throws SQLException {
        when(resultSet.getObject(COLUMN, OffsetDateTime.class)).thenReturn(null);

        assertNull(JdbcTimestamps.readInstant(resultSet, COLUMN));
    }
}
