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

import static com.irurueta.authserver.authorization.infrastructure.persistence.JdbcTimestamps.toTimestamp;

import com.irurueta.authserver.authorization.domain.mfa.SecondFactorAttemptRepository;
import com.irurueta.authserver.authorization.domain.mfa.SecondFactorLockout;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link SecondFactorAttemptRepository} over the {@code second_factor_attempts} table.
 */
@Repository
@RequiredArgsConstructor
public class JdbcSecondFactorAttemptRepository implements SecondFactorAttemptRepository {

    /** Query returning the state of a user. */
    private static final String FIND_ATTEMPTS = """
            SELECT failed_count, locked_until FROM second_factor_attempts WHERE user_id = ?
            """;

    // tag::mfa-lock-attempts[]
    /** Statement that creates the clean state of a user unless one exists, so there is always a row to lock. */
    private static final String ENSURE_ATTEMPTS = """
            INSERT INTO second_factor_attempts (user_id, failed_count) VALUES (?, 0)
            ON CONFLICT (user_id) DO NOTHING
            """;

    /**
     * Query returning the state of a user and locking its row until the end of the transaction: a concurrent
     * verification of the same user waits here until the first one commits.
     */
    private static final String LOCK_ATTEMPTS = """
            SELECT failed_count, locked_until FROM second_factor_attempts WHERE user_id = ? FOR UPDATE
            """;
    // end::mfa-lock-attempts[]

    /** Statement that clears the counter and the lock, keeping the row so later verifications can lock it. */
    private static final String RESET_ATTEMPTS = """
            UPDATE second_factor_attempts SET failed_count = 0, locked_until = NULL WHERE user_id = ?
            """;

    // tag::mfa-record-failure[]
    /**
     * Single-statement upsert that counts one failure and sets the lock when the maximum is reached. A lock that
     * has already ended restarts the counter at one. Concurrent failures serialize on the row, so none is lost.
     */
    private static final String RECORD_FAILURE = """
            INSERT INTO second_factor_attempts AS t (user_id, failed_count, locked_until)
            VALUES (:userId, 1, CASE WHEN 1 >= :maxAttempts THEN :lockedUntil ELSE NULL END)
            ON CONFLICT (user_id) DO UPDATE SET
                failed_count = CASE WHEN t.locked_until IS NOT NULL AND t.locked_until <= :now
                                    THEN 1 ELSE t.failed_count + 1 END,
                locked_until = CASE
                    WHEN (CASE WHEN t.locked_until IS NOT NULL AND t.locked_until <= :now
                               THEN 1 ELSE t.failed_count + 1 END) >= :maxAttempts THEN :lockedUntil
                    WHEN t.locked_until <= :now THEN NULL
                    ELSE t.locked_until END
            RETURNING failed_count, locked_until
            """;
    // end::mfa-record-failure[]

    /** JDBC client used to run the statements. */
    private final JdbcClient jdbcClient;

    /** Maps a row to the state of a user. */
    private final SecondFactorLockoutRowMapper secondFactorLockoutRowMapper;

    @Override
    public SecondFactorLockout find(final UUID userId) {
        return jdbcClient.sql(FIND_ATTEMPTS).param(userId).query(secondFactorLockoutRowMapper).optional()
                .orElseGet(SecondFactorLockout::none);
    }

    /**
     * Reads and locks the state of a user, in the caller's transaction (without one, the lock is released as soon
     * as the query ends).
     *
     * @param userId identifier of the user.
     * @return the state.
     */
    @Override
    public SecondFactorLockout lockForUpdate(final UUID userId) {
        jdbcClient.sql(ENSURE_ATTEMPTS).param(userId).update();
        return jdbcClient.sql(LOCK_ATTEMPTS).param(userId).query(secondFactorLockoutRowMapper).optional()
                .orElseGet(SecondFactorLockout::none);
    }

    @Override
    public SecondFactorLockout recordFailure(final UUID userId, final int maxAttempts, final Duration lockout,
                                             final Instant now) {
        return jdbcClient.sql(RECORD_FAILURE)
                .params(Map.of("userId", userId, "maxAttempts", maxAttempts, "now", toTimestamp(now),
                        "lockedUntil", toTimestamp(now.plus(lockout))))
                .query(secondFactorLockoutRowMapper)
                .single();
    }

    @Override
    public void reset(final UUID userId) {
        jdbcClient.sql(RESET_ATTEMPTS).param(userId).update();
    }
}
