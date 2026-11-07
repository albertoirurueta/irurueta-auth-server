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

import static com.irurueta.authserver.authorization.infrastructure.persistence.JdbcTimestamps.readInstant;

import com.irurueta.authserver.authorization.domain.ott.OneTimeCode;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;

/**
 * Maps a row of the {@code ott_codes} table to a {@link OneTimeCode}.
 */
@Component
public class OneTimeCodeRowMapper implements RowMapper<OneTimeCode> {

    /**
     * Maps the current row.
     *
     * @param rs     result set positioned on the row.
     * @param rowNum number of the row.
     * @return the code.
     * @throws SQLException if a column cannot be read.
     */
    @Override
    public OneTimeCode mapRow(final ResultSet rs, final int rowNum) throws SQLException {
        return new OneTimeCode(rs.getObject("id", UUID.class), rs.getString("username"),
                OttChannel.valueOf(rs.getString("channel")), OttPurpose.valueOf(rs.getString("purpose")),
                rs.getString("code_hash"), rs.getString("binding_id"), rs.getInt("attempts"),
                readInstant(rs, "expires_at"), readInstant(rs, "created_at"));
    }
}
