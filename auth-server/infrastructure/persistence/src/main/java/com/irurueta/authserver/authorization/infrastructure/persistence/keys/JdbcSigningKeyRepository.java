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

package com.irurueta.authserver.authorization.infrastructure.persistence.keys;

import static com.irurueta.authserver.authorization.infrastructure.persistence.JdbcTimestamps.toTimestamp;

import com.irurueta.authserver.authorization.domain.keys.SigningKey;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyRepository;
import java.util.List;
import java.util.function.Supplier;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * {@link SigningKeyRepository} over the {@code signing_keys} table. Rotation is serialised across application
 * instances with a PostgreSQL transaction-level advisory lock.
 */
@Repository
@RequiredArgsConstructor
public class JdbcSigningKeyRepository implements SigningKeyRepository {

    /** Key of the advisory lock that serialises rotations. */
    static final long ROTATION_LOCK_KEY = 5_203_341_870_000_001L;

    /** Query returning every key, oldest first. */
    private static final String FIND_ALL = """
            SELECT kid, alg, public_jwk, private_jwk_encrypted, status, created_at, activated_at, retired_at
            FROM signing_keys ORDER BY created_at, kid
            """;

    /** Statement inserting a key, or replacing the state of the key that has the same kid. */
    private static final String UPSERT = """
            INSERT INTO signing_keys (kid, alg, public_jwk, private_jwk_encrypted, status, created_at, activated_at,
                                      retired_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (kid) DO UPDATE SET status = EXCLUDED.status, activated_at = EXCLUDED.activated_at,
                retired_at = EXCLUDED.retired_at
            """;

    /** JDBC client used to run the statements. */
    private final JdbcClient jdbcClient;

    /** Template that runs the rotation inside a transaction. */
    private final TransactionTemplate transactionTemplate;

    /** Maps a row to a key. */
    private final SigningKeyRowMapper signingKeyRowMapper;

    @Override
    public List<SigningKey> findAll() {
        return jdbcClient.sql(FIND_ALL).query(signingKeyRowMapper).list();
    }

    @Override
    public void save(final SigningKey key) {
        jdbcClient.sql(UPSERT)
                .params(key.kid(), key.alg(), key.publicJwk(), key.encryptedPrivateJwk(), key.status().name(),
                        toTimestamp(key.createdAt()), toTimestamp(key.activatedAt()), toTimestamp(key.retiredAt()))
                .update();
    }

    @Override
    public void deleteByKid(final String kid) {
        jdbcClient.sql("DELETE FROM signing_keys WHERE kid = ?").param(kid).update();
    }

    // tag::keys-rotation-lock[]
    @Override
    public <T> T withRotationLock(final Supplier<T> action) {
        return transactionTemplate.execute(status -> {
            // the lock is released when the transaction ends; the row mapper only drains the (void) result
            jdbcClient.sql("SELECT pg_advisory_xact_lock(?)").param(ROTATION_LOCK_KEY)
                    .query((rs, rowNum) -> Boolean.TRUE).list();
            return action.get();
        });
    }
    // end::keys-rotation-lock[]
}
