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

import com.irurueta.authserver.authorization.domain.totp.TotpCredential;
import com.irurueta.authserver.authorization.domain.totp.TotpCredentialRepository;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link TotpCredentialRepository} over the {@code totp_credentials} table.
 */
@Repository
@RequiredArgsConstructor
public class JdbcTotpCredentialRepository implements TotpCredentialRepository {

    /** Query returning the credential of a user. */
    private static final String FIND_BY_USER = """
            SELECT user_id, encrypted_secret, confirmed, last_used_step, created_at FROM totp_credentials
            WHERE user_id = ?
            """;

    /** Statement inserting a credential, or replacing the one of the same user. */
    private static final String UPSERT = """
            INSERT INTO totp_credentials (user_id, encrypted_secret, confirmed, last_used_step, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (user_id) DO UPDATE SET encrypted_secret = EXCLUDED.encrypted_secret,
                confirmed = EXCLUDED.confirmed, last_used_step = EXCLUDED.last_used_step,
                created_at = EXCLUDED.created_at
            """;

    /** Statement confirming the credential of a user. */
    private static final String CONFIRM = "UPDATE totp_credentials SET confirmed = TRUE WHERE user_id = ?";

    /** Statement that records a step only when it is newer than the stored one, atomically. */
    private static final String ADVANCE_LAST_USED_STEP = """
            UPDATE totp_credentials SET last_used_step = ?
            WHERE user_id = ? AND last_used_step < ?
            """;

    /** Statement deleting the credential of a user. */
    private static final String DELETE_BY_USER = "DELETE FROM totp_credentials WHERE user_id = ?";

    /** JDBC client used to run the statements. */
    private final JdbcClient jdbcClient;

    /** Maps a row to a credential. */
    private final TotpCredentialRowMapper totpCredentialRowMapper;

    @Override
    public Optional<TotpCredential> findByUser(final UUID userId) {
        return jdbcClient.sql(FIND_BY_USER).param(userId).query(totpCredentialRowMapper).optional();
    }

    @Override
    public void save(final TotpCredential credential) {
        jdbcClient.sql(UPSERT)
                .params(credential.userId(), credential.encryptedSecret(), credential.confirmed(),
                        credential.lastUsedStep(), toTimestamp(credential.createdAt()))
                .update();
    }

    @Override
    public void confirm(final UUID userId) {
        jdbcClient.sql(CONFIRM).param(userId).update();
    }

    @Override
    public boolean advanceLastUsedStep(final UUID userId, final long step) {
        return jdbcClient.sql(ADVANCE_LAST_USED_STEP).params(step, userId, step).update() > 0;
    }

    @Override
    public void deleteByUser(final UUID userId) {
        jdbcClient.sql(DELETE_BY_USER).param(userId).update();
    }
}
