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

import static com.irurueta.authserver.authorization.infrastructure.persistence.JdbcTimestamps.toTimestamp;

import com.irurueta.authserver.authorization.domain.sms.PhoneVerification;
import com.irurueta.authserver.authorization.domain.sms.PhoneVerificationRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link PhoneVerificationRepository} over the {@code pending_*} columns of the {@code user_phones} table. It opens
 * no transaction: clearing a verification and then deleting an empty row runs in the caller's.
 */
@Repository
@RequiredArgsConstructor
public class JdbcPhoneVerificationRepository implements PhoneVerificationRepository {

    /** Statement storing the pending verification of a user, creating the row if needed. */
    private static final String UPSERT = """
            INSERT INTO user_phones (user_id, pending_phone_e164, pending_code_hash, pending_attempts,
                                     pending_expires_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (user_id) DO UPDATE
            SET pending_phone_e164 = EXCLUDED.pending_phone_e164,
                pending_code_hash = EXCLUDED.pending_code_hash,
                pending_attempts = EXCLUDED.pending_attempts,
                pending_expires_at = EXCLUDED.pending_expires_at
            """;

    /** Query returning the pending verification of a user. */
    private static final String FIND_BY_USER = """
            SELECT user_id, pending_phone_e164, pending_code_hash, pending_attempts, pending_expires_at
            FROM user_phones
            WHERE user_id = ? AND pending_phone_e164 IS NOT NULL
            """;

    /** Statement counting a failed attempt atomically and returning the new count. */
    private static final String INCREMENT_ATTEMPTS = """
            UPDATE user_phones SET pending_attempts = pending_attempts + 1
            WHERE user_id = ? AND pending_phone_e164 IS NOT NULL
            RETURNING pending_attempts
            """;

    /** Statement clearing the pending columns of a user. */
    private static final String CLEAR_PENDING = """
            UPDATE user_phones
            SET pending_phone_e164 = NULL, pending_code_hash = NULL, pending_attempts = 0, pending_expires_at = NULL
            WHERE user_id = ?
            """;

    /** Statement deleting the row of a user that holds neither a verified phone nor a pending verification. */
    private static final String DELETE_IF_EMPTY =
            "DELETE FROM user_phones WHERE user_id = ? AND phone_e164 IS NULL AND pending_phone_e164 IS NULL";

    /** Statement clearing every expired pending verification. */
    private static final String CLEAR_EXPIRED = """
            UPDATE user_phones
            SET pending_phone_e164 = NULL, pending_code_hash = NULL, pending_attempts = 0, pending_expires_at = NULL
            WHERE pending_expires_at <= ?
            """;

    /** Statement deleting the rows that hold nothing at all. */
    private static final String DELETE_EMPTY_ROWS =
            "DELETE FROM user_phones WHERE phone_e164 IS NULL AND pending_phone_e164 IS NULL";

    /** JDBC client used to run the statements. */
    private final JdbcClient jdbcClient;

    /** Maps a row to a verification. */
    private final PhoneVerificationRowMapper phoneVerificationRowMapper;

    @Override
    public void save(final PhoneVerification verification) {
        jdbcClient.sql(UPSERT)
                .params(verification.userId(), verification.phone().e164(), verification.codeHash(),
                        verification.attempts(), toTimestamp(verification.expiresAt()))
                .update();
    }

    @Override
    public Optional<PhoneVerification> findByUserId(final UUID userId) {
        return jdbcClient.sql(FIND_BY_USER).param(userId).query(phoneVerificationRowMapper).optional();
    }

    @Override
    public int incrementAttempts(final UUID userId) {
        return jdbcClient.sql(INCREMENT_ATTEMPTS).param(userId).query(Integer.class).optional().orElse(0);
    }

    @Override
    public void deleteByUserId(final UUID userId) {
        jdbcClient.sql(CLEAR_PENDING).param(userId).update();
        jdbcClient.sql(DELETE_IF_EMPTY).param(userId).update();
    }

    @Override
    public int deleteExpired(final Instant now) {
        final var cleared = jdbcClient.sql(CLEAR_EXPIRED).param(toTimestamp(now)).update();
        jdbcClient.sql(DELETE_EMPTY_ROWS).update();
        return cleared;
    }
}
