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

import static com.irurueta.authserver.authorization.infrastructure.persistence.JdbcTimestamps.toTimestamp;

import com.irurueta.authserver.authorization.domain.totp.RecoveryCode;
import com.irurueta.authserver.authorization.domain.totp.RecoveryCodeRepository;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link RecoveryCodeRepository} over the {@code recovery_codes} table. It opens no transaction: replacing the codes
 * of a user runs in the caller's.
 */
@Repository
@RequiredArgsConstructor
public class JdbcRecoveryCodeRepository implements RecoveryCodeRepository {

    /** Statement deleting every code of a user. */
    private static final String DELETE_BY_USER = "DELETE FROM recovery_codes WHERE user_id = ?";

    /** Statement storing a code. */
    private static final String INSERT = """
            INSERT INTO recovery_codes (id, user_id, hashed_code, used_at)
            VALUES (?, ?, ?, ?)
            """;

    /** Query returning the codes of a user that have not been spent. */
    private static final String FIND_UNUSED = """
            SELECT id, user_id, hashed_code, used_at FROM recovery_codes
            WHERE user_id = ? AND used_at IS NULL
            ORDER BY created_at, id
            """;

    /** Statement that spends a code only when it is unused, atomically. */
    private static final String MARK_USED = "UPDATE recovery_codes SET used_at = ? WHERE id = ? AND used_at IS NULL";

    /** JDBC client used to run the statements. */
    private final JdbcClient jdbcClient;

    /** Maps a row to a code. */
    private final RecoveryCodeRowMapper recoveryCodeRowMapper;

    @Override
    public void replaceAll(final UUID userId, final List<RecoveryCode> codes) {
        deleteByUser(userId);
        codes.forEach(code -> jdbcClient.sql(INSERT)
                .params(code.id(), userId, code.hashedCode(), toTimestamp(code.usedAt()))
                .update());
    }

    @Override
    public List<RecoveryCode> findUnused(final UUID userId) {
        return jdbcClient.sql(FIND_UNUSED).param(userId).query(recoveryCodeRowMapper).list();
    }

    @Override
    public boolean markUsed(final UUID id, final Instant now) {
        return jdbcClient.sql(MARK_USED).params(toTimestamp(now), id).update() > 0;
    }

    @Override
    public void deleteByUser(final UUID userId) {
        jdbcClient.sql(DELETE_BY_USER).param(userId).update();
    }
}
