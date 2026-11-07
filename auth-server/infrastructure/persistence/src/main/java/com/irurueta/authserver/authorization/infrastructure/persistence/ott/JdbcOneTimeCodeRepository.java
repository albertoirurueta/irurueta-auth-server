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

import static com.irurueta.authserver.authorization.infrastructure.persistence.JdbcTimestamps.toTimestamp;

import com.irurueta.authserver.authorization.domain.ott.OneTimeCode;
import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link OneTimeCodeRepository} over the {@code ott_codes} table. It opens no transaction: replacing a code runs in
 * the caller's, and every other operation is a single statement.
 */
@Repository
@RequiredArgsConstructor
public class JdbcOneTimeCodeRepository implements OneTimeCodeRepository {

    /** Statement deleting the codes of a binding and a user name. */
    private static final String DELETE_BY_BINDING = "DELETE FROM ott_codes WHERE binding_id = ? AND username = ?";

    /** Statement storing a code. */
    private static final String INSERT = """
            INSERT INTO ott_codes (id, username, channel, purpose, code_hash, binding_id, attempts, expires_at,
                                   created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """;

    /** Query returning the newest unexpired code of a binding and a user name. */
    private static final String FIND_ACTIVE = """
            SELECT id, username, channel, purpose, code_hash, binding_id, attempts, expires_at, created_at
            FROM ott_codes
            WHERE binding_id = ? AND username = ? AND expires_at > ?
            ORDER BY created_at DESC
            LIMIT 1
            """;

    /** Statement counting a failed attempt atomically and returning the new count. */
    private static final String INCREMENT_ATTEMPTS =
            "UPDATE ott_codes SET attempts = attempts + 1 WHERE id = ? RETURNING attempts";

    /** Statement spending a code. */
    private static final String CONSUME = "DELETE FROM ott_codes WHERE id = ?";

    /** Statement deleting the expired codes. */
    private static final String DELETE_EXPIRED = "DELETE FROM ott_codes WHERE expires_at <= ?";

    /** JDBC client used to run the statements. */
    private final JdbcClient jdbcClient;

    /** Maps a row to a code. */
    private final OneTimeCodeRowMapper oneTimeCodeRowMapper;

    @Override
    public void save(final OneTimeCode code) {
        jdbcClient.sql(DELETE_BY_BINDING).params(code.bindingId(), code.username()).update();
        jdbcClient.sql(INSERT)
                .params(code.id(), code.username(), code.channel().name(), code.purpose().name(), code.codeHash(),
                        code.bindingId(), code.attempts(), toTimestamp(code.expiresAt()),
                        toTimestamp(code.createdAt()))
                .update();
    }

    @Override
    public Optional<OneTimeCode> findActive(final String bindingId, final String username, final Instant now) {
        return jdbcClient.sql(FIND_ACTIVE)
                .params(bindingId, username, toTimestamp(now))
                .query(oneTimeCodeRowMapper)
                .optional();
    }

    @Override
    public int incrementAttempts(final UUID id) {
        return jdbcClient.sql(INCREMENT_ATTEMPTS).param(id).query(Integer.class).optional().orElse(0);
    }

    @Override
    public boolean consume(final UUID id) {
        return jdbcClient.sql(CONSUME).param(id).update() > 0;
    }

    @Override
    public int deleteExpired(final Instant now) {
        return jdbcClient.sql(DELETE_EXPIRED).param(toTimestamp(now)).update();
    }
}
