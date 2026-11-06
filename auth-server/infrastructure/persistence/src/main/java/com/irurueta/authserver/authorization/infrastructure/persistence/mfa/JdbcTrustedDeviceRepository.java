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

import com.irurueta.authserver.authorization.domain.mfa.TrustedDevice;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link TrustedDeviceRepository} over the {@code trusted_devices} table. It joins the transaction of its caller.
 */
@Repository
@RequiredArgsConstructor
public class JdbcTrustedDeviceRepository implements TrustedDeviceRepository {

    /** Columns selected for every query. */
    private static final String COLUMNS = "id, user_id, hashed_token, user_agent, expires_at, created_at";

    /** Statement storing a device. */
    private static final String INSERT_DEVICE = """
            INSERT INTO trusted_devices (id, user_id, hashed_token, user_agent, expires_at, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """;

    /** Query returning an unexpired device of a user by the hash of its token. */
    private static final String FIND_USABLE = "SELECT " + COLUMNS
            + " FROM trusted_devices WHERE user_id = ? AND hashed_token = ? AND expires_at > ?";

    /** Query returning the unexpired devices of a user, newest first. */
    private static final String FIND_BY_USER = "SELECT " + COLUMNS
            + " FROM trusted_devices WHERE user_id = ? AND expires_at > ? ORDER BY created_at DESC";

    /** JDBC client used to run the statements. */
    private final JdbcClient jdbcClient;

    /** Maps a row to a device. */
    private final TrustedDeviceRowMapper trustedDeviceRowMapper;

    @Override
    public void store(final TrustedDevice device) {
        jdbcClient.sql(INSERT_DEVICE)
                .params(device.id(), device.userId(), device.hashedToken(), device.userAgentSummary(),
                        toTimestamp(device.expiresAt()), toTimestamp(device.createdAt()))
                .update();
    }

    @Override
    public Optional<TrustedDevice> findUsable(final UUID userId, final String hashedToken, final Instant now) {
        return jdbcClient.sql(FIND_USABLE).params(userId, hashedToken, toTimestamp(now))
                .query(trustedDeviceRowMapper)
                .optional();
    }

    @Override
    public List<TrustedDevice> findByUser(final UUID userId, final Instant now) {
        return jdbcClient.sql(FIND_BY_USER).params(userId, toTimestamp(now)).query(trustedDeviceRowMapper).list();
    }

    @Override
    public boolean revoke(final UUID userId, final UUID id) {
        return jdbcClient.sql("DELETE FROM trusted_devices WHERE user_id = ? AND id = ?").params(userId, id)
                .update() > 0;
    }

    @Override
    public int deleteExpired(final Instant now) {
        return jdbcClient.sql("DELETE FROM trusted_devices WHERE expires_at <= ?").param(toTimestamp(now)).update();
    }
}
