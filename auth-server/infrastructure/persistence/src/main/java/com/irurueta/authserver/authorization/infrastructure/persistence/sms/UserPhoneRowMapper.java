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

package com.irurueta.authserver.authorization.infrastructure.persistence.sms;

import static com.irurueta.authserver.authorization.infrastructure.persistence.JdbcTimestamps.readInstant;

import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.UserPhone;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;

/**
 * Maps the verified columns of a row of the {@code user_phones} table to a {@link UserPhone}.
 */
@Component
public class UserPhoneRowMapper implements RowMapper<UserPhone> {

    /**
     * Maps the current row.
     *
     * @param rs     result set positioned on a row whose verified columns are not null.
     * @param rowNum number of the row.
     * @return the verified phone.
     * @throws SQLException if a column cannot be read.
     */
    @Override
    public UserPhone mapRow(final ResultSet rs, final int rowNum) throws SQLException {
        return new UserPhone(rs.getObject("user_id", UUID.class), new PhoneNumber(rs.getString("phone_e164")),
                readInstant(rs, "verified_at"));
    }
}
