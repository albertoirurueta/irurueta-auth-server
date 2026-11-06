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

import static com.irurueta.authserver.authorization.infrastructure.persistence.JdbcTimestamps.readInstant;

import com.irurueta.authserver.authorization.domain.mfa.SecondFactorLockout;
import java.sql.ResultSet;
import java.sql.SQLException;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.stereotype.Component;

/**
 * Maps a row of the {@code second_factor_attempts} table to a {@link SecondFactorLockout}.
 */
@Component
public class SecondFactorLockoutRowMapper implements RowMapper<SecondFactorLockout> {

    /**
     * Maps the current row.
     *
     * @param rs     result set positioned on the row.
     * @param rowNum number of the row.
     * @return the state; its lock end is {@code null} when the second factor is not locked.
     * @throws SQLException if a column cannot be read.
     */
    @Override
    public SecondFactorLockout mapRow(final ResultSet rs, final int rowNum) throws SQLException {
        return new SecondFactorLockout(rs.getInt("failed_count"), readInstant(rs, "locked_until"));
    }
}
