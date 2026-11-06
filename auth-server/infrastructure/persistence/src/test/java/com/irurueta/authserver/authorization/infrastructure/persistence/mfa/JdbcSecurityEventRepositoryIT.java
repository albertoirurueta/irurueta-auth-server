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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.mfa.SecurityEvent;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Integration tests of {@link JdbcSecurityEventRepository} against a migrated PostgreSQL.
 */
class JdbcSecurityEventRepositoryIT {

    /** Page size larger than the data of the tests. */
    private static final int LIMIT = 10;

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Repository under test. */
    private static JdbcSecurityEventRepository repository;

    /** Identifier of the user that owns the events. */
    private UUID userId;

    /**
     * Connects to the migrated database and builds the repository.
     */
    @BeforeAll
    static void connect() {
        jdbcClient = JdbcClient.create(MigratedPostgres.dataSource());
        repository = new JdbcSecurityEventRepository(jdbcClient, new SecurityEventRowMapper());
    }

    /**
     * Removes the data of the previous test and inserts the user that owns the events.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM security_events").update();
        jdbcClient.sql("DELETE FROM users").update();
        userId = UUID.randomUUID();
        jdbcClient.sql("INSERT INTO users (id, username) VALUES (?, ?)").params(userId, "user-" + userId).update();
    }

    /**
     * Verifies that the events of the user are returned newest first, limited, and without other users' events.
     */
    @Test
    void findRecentByUser_whenEventsExist_returnsNewestFirstAndLimited() {
        final var now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        repository.store(new SecurityEvent(SecurityEventType.LOGIN_SUCCESS, userId, "u", null, now.minusSeconds(2)));
        repository.store(new SecurityEvent(SecurityEventType.SECOND_FACTOR_FAILURE, userId, "u", "bad", now));
        repository.store(new SecurityEvent(SecurityEventType.LOGIN_FAILURE, null, "ghost", null, now));

        final var all = repository.findRecentByUser(userId, LIMIT);
        final var limited = repository.findRecentByUser(userId, 1);

        assertEquals(2, all.size());
        assertEquals(SecurityEventType.SECOND_FACTOR_FAILURE, all.getFirst().type());
        assertEquals("bad", all.getFirst().detail());
        assertEquals(now, all.getFirst().occurredAt());
        assertEquals(1, limited.size());
    }

    /**
     * Verifies that a user without events has an empty list.
     */
    @Test
    void findRecentByUser_whenNoEvents_returnsEmptyList() {
        assertTrue(repository.findRecentByUser(userId, LIMIT).isEmpty());
    }
}
