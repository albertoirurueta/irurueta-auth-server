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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.mfa.SecondFactorLockout;
import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Integration tests of {@link JdbcSecondFactorAttemptRepository} against a migrated PostgreSQL.
 */
class JdbcSecondFactorAttemptRepositoryIT {

    /** Failures that trigger the lock. */
    private static final int MAX_ATTEMPTS = 3;

    /** Lock duration. */
    private static final Duration LOCKOUT = Duration.ofMinutes(15);

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Repository under test. */
    private static JdbcSecondFactorAttemptRepository repository;

    /** Identifier of the user. */
    private UUID userId;

    /**
     * Connects to the migrated database and builds the repository.
     */
    @BeforeAll
    static void connect() {
        jdbcClient = JdbcClient.create(MigratedPostgres.dataSource());
        repository = new JdbcSecondFactorAttemptRepository(jdbcClient, new SecondFactorLockoutRowMapper());
    }

    /**
     * Removes the data of the previous test and inserts the user.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM users").update();
        userId = UUID.randomUUID();
        jdbcClient.sql("INSERT INTO users (id, username) VALUES (?, ?)").params(userId, "user-" + userId).update();
    }

    /**
     * Verifies that a user with no failures has a clean state.
     */
    @Test
    void find_whenNothingRecorded_returnsNone() {
        assertEquals(SecondFactorLockout.none(), repository.find(userId));
    }

    /**
     * Verifies that failures are counted and the lock is set exactly when the maximum is reached.
     */
    @Test
    void recordFailure_whenMaximumReached_locksTheSecondFactor() {
        final var now = Instant.now().truncatedTo(ChronoUnit.MILLIS);

        final var first = repository.recordFailure(userId, MAX_ATTEMPTS, LOCKOUT, now);
        final var second = repository.recordFailure(userId, MAX_ATTEMPTS, LOCKOUT, now);
        final var third = repository.recordFailure(userId, MAX_ATTEMPTS, LOCKOUT, now);

        assertEquals(1, first.failedCount());
        assertNull(first.lockedUntil());
        assertEquals(2, second.failedCount());
        assertFalse(second.isLocked(now));
        assertEquals(MAX_ATTEMPTS, third.failedCount());
        assertEquals(now.plus(LOCKOUT), third.lockedUntil());
        assertTrue(repository.find(userId).isLocked(now));
    }

    /**
     * Verifies that a failure after the lock ended restarts the counter.
     */
    @Test
    void recordFailure_whenPreviousLockEnded_restartsTheCounter() {
        final var now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        for (var i = 0; i < MAX_ATTEMPTS; i++) {
            repository.recordFailure(userId, MAX_ATTEMPTS, LOCKOUT, now);
        }

        final var later = repository.recordFailure(userId, MAX_ATTEMPTS, LOCKOUT, now.plus(LOCKOUT).plusSeconds(1));

        assertEquals(1, later.failedCount());
        assertNull(later.lockedUntil());
    }

    /**
     * Verifies that a reset clears the counter and the lock.
     */
    @Test
    void reset_whenLocked_clearsTheState() {
        final var now = Instant.now();
        for (var i = 0; i < MAX_ATTEMPTS; i++) {
            repository.recordFailure(userId, MAX_ATTEMPTS, LOCKOUT, now);
        }

        repository.reset(userId);

        assertEquals(SecondFactorLockout.none(), repository.find(userId));
    }
}
