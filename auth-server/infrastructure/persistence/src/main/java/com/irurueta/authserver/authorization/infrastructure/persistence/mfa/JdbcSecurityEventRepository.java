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

import com.irurueta.authserver.authorization.domain.mfa.SecurityEvent;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventRepository;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/**
 * {@link SecurityEventRepository} over the {@code security_events} table.
 */
@Repository
@RequiredArgsConstructor
public class JdbcSecurityEventRepository implements SecurityEventRepository {

    /** Statement storing an event; the database generates its identifier. */
    private static final String INSERT_EVENT = """
            INSERT INTO security_events (id, type, user_id, username, detail, occurred_at)
            VALUES (gen_random_uuid(), ?, ?, ?, ?, ?)
            """;

    /** Query returning the latest events of a user, newest first. */
    private static final String FIND_RECENT_BY_USER = """
            SELECT type, user_id, username, detail, occurred_at FROM security_events
            WHERE user_id = ? ORDER BY occurred_at DESC, id LIMIT ?
            """;

    /** JDBC client used to run the statements. */
    private final JdbcClient jdbcClient;

    /** Maps a row to an event. */
    private final SecurityEventRowMapper securityEventRowMapper;

    @Override
    public void store(final SecurityEvent event) {
        jdbcClient.sql(INSERT_EVENT)
                .params(event.type().name(), event.userId(), event.username(), event.detail(),
                        toTimestamp(event.occurredAt()))
                .update();
    }

    @Override
    public List<SecurityEvent> findRecentByUser(final UUID userId, final int limit) {
        return jdbcClient.sql(FIND_RECENT_BY_USER).params(userId, limit).query(securityEventRowMapper).list();
    }
}
