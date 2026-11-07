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

import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.UserPhone;
import com.irurueta.authserver.authorization.domain.sms.UserPhoneRepository;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link UserPhoneRepository} over the verified columns of the {@code user_phones} table. It opens no transaction: a
 * save runs in the caller's, where it first takes a PostgreSQL transaction-level advisory lock on the number, so two
 * users confirming the same number are serialised and the unique constraint is never violated (a violation would
 * abort the caller's transaction).
 */
@Repository
@RequiredArgsConstructor
public class JdbcUserPhoneRepository implements UserPhoneRepository {

    /** First key of the advisory locks of the numbers, which keeps them apart from every other advisory lock. */
    static final int PHONE_LOCK_NAMESPACE = 620;

    /** Query returning the verified phone of a user. */
    private static final String FIND_BY_USER = """
            SELECT user_id, phone_e164, verified_at FROM user_phones
            WHERE user_id = ? AND phone_e164 IS NOT NULL
            """;

    /** Query returning the verified phone with a number. */
    private static final String FIND_BY_PHONE = """
            SELECT user_id, phone_e164, verified_at FROM user_phones WHERE phone_e164 = ?
            """;

    /** Statement taking the advisory lock of a number, released when the caller's transaction ends. */
    private static final String LOCK_NUMBER = "SELECT pg_advisory_xact_lock(?, hashtext(?))";

    /**
     * Statement that stores the verified phone of a user, creating the row or updating its verified columns only
     * (the pending ones are untouched), unless another user already owns the number. It runs after the lock of the
     * number is taken, so (in the default {@code READ COMMITTED} isolation) it sees the row of any user who confirmed
     * the same number before, and the unique constraint cannot be hit.
     */
    private static final String UPSERT = """
            INSERT INTO user_phones (user_id, phone_e164, verified_at)
            SELECT ?::uuid, ?::varchar, ?::timestamptz
            WHERE NOT EXISTS (SELECT 1 FROM user_phones WHERE phone_e164 = ? AND user_id <> ?)
            ON CONFLICT (user_id) DO UPDATE
            SET phone_e164 = EXCLUDED.phone_e164, verified_at = EXCLUDED.verified_at
            """;

    /** Statement clearing the verified columns of a user. */
    private static final String CLEAR_VERIFIED =
            "UPDATE user_phones SET phone_e164 = NULL, verified_at = NULL WHERE user_id = ?";

    /** Statement deleting the row of a user that holds neither a verified phone nor a pending verification. */
    private static final String DELETE_IF_EMPTY =
            "DELETE FROM user_phones WHERE user_id = ? AND phone_e164 IS NULL AND pending_phone_e164 IS NULL";

    /** JDBC client used to run the statements. */
    private final JdbcClient jdbcClient;

    /** Maps a row to a verified phone. */
    private final UserPhoneRowMapper userPhoneRowMapper;

    @Override
    public Optional<UserPhone> findByUserId(final UUID userId) {
        return jdbcClient.sql(FIND_BY_USER).param(userId).query(userPhoneRowMapper).optional();
    }

    @Override
    public Optional<UserPhone> findByPhone(final PhoneNumber phone) {
        return jdbcClient.sql(FIND_BY_PHONE).param(phone.e164()).query(userPhoneRowMapper).optional();
    }

    @Override
    public boolean save(final UserPhone phone) {
        final var e164 = phone.phone().e164();
        // the row mapper only drains the (void) result of the lock function
        jdbcClient.sql(LOCK_NUMBER).params(PHONE_LOCK_NAMESPACE, e164).query((rs, rowNum) -> Boolean.TRUE).list();
        return jdbcClient.sql(UPSERT)
                .params(phone.userId(), e164, toTimestamp(phone.verifiedAt()), e164, phone.userId())
                .update() > 0;
    }

    @Override
    public void deleteByUserId(final UUID userId) {
        jdbcClient.sql(CLEAR_VERIFIED).param(userId).update();
        jdbcClient.sql(DELETE_IF_EMPTY).param(userId).update();
    }
}
