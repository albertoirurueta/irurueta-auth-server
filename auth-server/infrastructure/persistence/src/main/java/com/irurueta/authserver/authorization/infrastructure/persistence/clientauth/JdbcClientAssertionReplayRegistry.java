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

package com.irurueta.authserver.authorization.infrastructure.persistence.clientauth;

import static com.irurueta.authserver.authorization.infrastructure.persistence.JdbcTimestamps.toTimestamp;

import com.irurueta.authserver.authorization.domain.clientauth.ClientAssertionReplayRegistry;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link ClientAssertionReplayRegistry} over the {@code client_assertion_jtis} table. Each method is a single
 * statement run in the caller's transaction. The primary key {@code (client_id, jti)} makes the insert atomic: of
 * concurrent registrations of the same pair exactly one inserts a row, the others do nothing and report a replay,
 * without a constraint violation that would abort the caller's transaction.
 */
@Repository
@RequiredArgsConstructor
public class JdbcClientAssertionReplayRegistry implements ClientAssertionReplayRegistry {

    /** Statement recording a first use; a replay inserts nothing. */
    private static final String INSERT = "INSERT INTO client_assertion_jtis (client_id, jti, expires_at) "
            + "VALUES (?, ?, ?) ON CONFLICT (client_id, jti) DO NOTHING";

    /** Statement deleting the expired identifiers. */
    private static final String DELETE_EXPIRED = "DELETE FROM client_assertion_jtis WHERE expires_at <= ?";

    /** JDBC client used to run the statements. */
    private final JdbcClient jdbcClient;

    @Override
    public boolean register(final String clientId, final String jti, final Instant expiresAt) {
        return jdbcClient.sql(INSERT).params(clientId, jti, toTimestamp(expiresAt)).update() == 1;
    }

    @Override
    public int purgeExpired(final Instant now) {
        return jdbcClient.sql(DELETE_EXPIRED).param(toTimestamp(now)).update();
    }
}
