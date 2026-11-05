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

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;

/**
 * Converts between the domain's {@link Instant} and the {@link OffsetDateTime} the PostgreSQL driver binds to and
 * reads from a {@code timestamp with time zone} column. Shared by every JDBC adapter of this module, so they all
 * store UTC values the same way.
 */
public final class JdbcTimestamps {

    /**
     * Not instantiable: a holder of stateless conversions.
     */
    private JdbcTimestamps() {
    }

    /**
     * Converts an instant to the value bound to a {@code timestamp with time zone} column.
     *
     * @param instant the instant, or {@code null}.
     * @return the equivalent UTC date time, or {@code null}.
     */
    public static OffsetDateTime toTimestamp(final Instant instant) {
        return instant == null ? null : instant.atOffset(ZoneOffset.UTC);
    }

    /**
     * Reads a {@code timestamp with time zone} column that may be null.
     *
     * @param rs     result set positioned on a row.
     * @param column name of the column.
     * @return the instant, or {@code null} when the column is null.
     * @throws SQLException if the column cannot be read.
     */
    public static Instant readInstant(final ResultSet rs, final String column) throws SQLException {
        final var value = rs.getObject(column, OffsetDateTime.class);
        return value == null ? null : value.toInstant();
    }
}
