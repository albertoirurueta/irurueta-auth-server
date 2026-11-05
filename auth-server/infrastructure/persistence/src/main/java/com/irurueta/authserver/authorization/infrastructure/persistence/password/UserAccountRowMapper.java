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

package com.irurueta.authserver.authorization.infrastructure.persistence.password;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;

// tag::password-load-user[]
/**
 * Maps a row of the {@code users} table joined with {@code user_passwords} to a {@link UserAccountRow}. The
 * authorities are not part of the row: the repository loads them with a second query.
 */
@Component
public class UserAccountRowMapper implements RowMapper<UserAccountRow> {

    /**
     * Maps the current row.
     *
     * @param rs     result set positioned on the row.
     * @param rowNum number of the row.
     * @return the row.
     * @throws SQLException if a column cannot be read.
     */
    @Override
    public UserAccountRow mapRow(final ResultSet rs, final int rowNum) throws SQLException {
        return new UserAccountRow(rs.getObject("id", UUID.class), rs.getString("username"),
                rs.getString("encoded_password"), rs.getBoolean("enabled"), rs.getString("email"),
                rs.getBoolean("email_verified"), rs.getString("tenant"));
    }
}
// end::password-load-user[]
