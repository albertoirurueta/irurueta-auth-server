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
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link UserPhoneRepository} over the verified columns of the {@code user_phones} table. It opens no transaction.
 */
@Repository
@RequiredArgsConstructor
public class JdbcUserPhoneRepository implements UserPhoneRepository {

    /** Query returning the verified phone of a user. */
    private static final String FIND_BY_USER = """
            SELECT user_id, phone_e164, verified_at FROM user_phones
            WHERE user_id = ? AND phone_e164 IS NOT NULL
            """;

    /** Query returning the verified phone with a number. */
    private static final String FIND_BY_PHONE = """
            SELECT user_id, phone_e164, verified_at FROM user_phones WHERE phone_e164 = ?
            """;

    /**
     * Statement that stores the verified phone of a user, creating the row or updating its verified columns only
     * (the pending ones are untouched), unless another user already owns the number. One statement, so the check
     * and the write cannot be separated by another statement of the same connection.
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

    /**
     * {@inheritDoc}
     *
     * <p>A concurrent insert of the same number by another user, between the ownership check and the write, makes
     * the unique constraint refuse the statement; that is also reported as {@code false}, but PostgreSQL then aborts
     * the caller's transaction, which must be rolled back.</p>
     */
    @Override
    public boolean save(final UserPhone phone) {
        try {
            return jdbcClient.sql(UPSERT)
                    .params(phone.userId(), phone.phone().e164(), toTimestamp(phone.verifiedAt()),
                            phone.phone().e164(), phone.userId())
                    .update() > 0;
        } catch (final DuplicateKeyException e) {
            return false;
        }
    }

    @Override
    public void deleteByUserId(final UUID userId) {
        jdbcClient.sql(CLEAR_VERIFIED).param(userId).update();
        jdbcClient.sql(DELETE_IF_EMPTY).param(userId).update();
    }
}
