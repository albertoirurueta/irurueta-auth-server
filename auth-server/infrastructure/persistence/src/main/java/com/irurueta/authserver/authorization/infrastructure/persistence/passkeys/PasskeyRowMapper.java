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

import com.irurueta.authserver.authorization.domain.passkeys.Passkey;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;

/**
 * Maps a row of the {@code user_credentials} table to a {@link Passkey}. The {@code created} and {@code last_used}
 * columns are plain {@code timestamp}s that Spring Security's own repository writes from epoch milliseconds, so they
 * are read back the same way.
 */
@Component
public class PasskeyRowMapper implements RowMapper<Passkey> {

    /**
     * Maps the current row.
     *
     * @param rs     result set positioned on the row.
     * @param rowNum number of the row.
     * @return the passkey; a row without a creation timestamp is given the epoch, since the domain requires one.
     * @throws SQLException if a column cannot be read.
     */
    @Override
    public Passkey mapRow(final ResultSet rs, final int rowNum) throws SQLException {
        return new Passkey(rs.getString("credential_id"), rs.getString("user_entity_user_id"),
                rs.getString("label"), readInstant(rs, "created", Instant.EPOCH), readInstant(rs, "last_used", null),
                rs.getLong("signature_count"), rs.getBoolean("backup_eligible"), rs.getBoolean("backup_state"));
    }

    /**
     * Reads a {@code timestamp} column that may be null.
     *
     * @param rs       result set positioned on a row.
     * @param column   name of the column.
     * @param fallback value returned when the column is null.
     * @return the instant, or the fallback.
     * @throws SQLException if the column cannot be read.
     */
    private static Instant readInstant(final ResultSet rs, final String column, final Instant fallback)
            throws SQLException {
        final var value = rs.getTimestamp(column);
        return value == null ? fallback : value.toInstant();
    }
}
