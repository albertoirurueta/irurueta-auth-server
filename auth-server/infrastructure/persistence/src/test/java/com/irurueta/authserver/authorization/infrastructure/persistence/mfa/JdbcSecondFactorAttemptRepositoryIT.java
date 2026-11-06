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
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Integration tests of {@link JdbcSecondFactorAttemptRepository} against a migrated PostgreSQL.
 */
class JdbcSecondFactorAttemptRepositoryIT {

    /** Failures that trigger the lock. */
    private static final int MAX_ATTEMPTS = 3;

    /** Lock duration. */
    private static final Duration LOCKOUT = Duration.ofMinutes(15);

    /** Longest wait for the probe of the row lock, in seconds. */
    private static final long PROBE_TIMEOUT_SECONDS = 30;

    /**
     * Query that tries to lock the row of a user without waiting: PostgreSQL fails it at once
     * ({@code lock_not_available}) while another transaction holds the lock.
     */
    private static final String TRY_LOCK = "SELECT failed_count FROM second_factor_attempts WHERE user_id = ? "
            + "FOR UPDATE NOWAIT";

    /** Runs the callbacks of the tests in a transaction of their own. */
    private static TransactionTemplate transactions;

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
        transactions = new TransactionTemplate(new DataSourceTransactionManager(MigratedPostgres.dataSource()));
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
     * Verifies that locking a user with no failures creates the clean state, so later verifications have a row to
     * lock.
     */
    @Test
    void lockForUpdate_whenNothingRecorded_createsAndReturnsTheCleanState() {
        assertEquals(SecondFactorLockout.none(), transactions.execute(status -> repository.lockForUpdate(userId)));
        assertEquals(1, jdbcClient.sql("SELECT count(*) FROM second_factor_attempts WHERE user_id = ?")
                .param(userId).query(Long.class).single());
    }

    /**
     * Verifies that the row stays locked until the transaction that locked it ends: another transaction cannot lock
     * it meanwhile, and can once the first one has committed. The row exists beforehand, as it does after the first
     * verification of a user (the very first one inserts it, and a concurrent insert waits for that one to commit).
     */
    @Test
    void lockForUpdate_whenTransactionIsOpen_blocksOtherTransactionsUntilItEnds() {
        repository.recordFailure(userId, MAX_ATTEMPTS, LOCKOUT, Instant.now());
        try (var executor = Executors.newSingleThreadExecutor()) {
            final var blocked = transactions.execute(status -> {
                repository.lockForUpdate(userId);
                return probe(executor);
            });
            assertEquals(Boolean.TRUE, blocked, "No other transaction may lock the row while the first one holds it");
            assertFalse(probe(executor), "The row must be free once the first transaction has committed");
        }
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

    /**
     * Tries, from another thread and so another connection and transaction, to lock the row of the user without
     * waiting.
     *
     * @param executor the thread to run the probe in.
     * @return {@code true} when the row is locked by someone else.
     */
    private boolean probe(final ExecutorService executor) {
        try {
            return executor.submit(() -> {
                try {
                    transactions.executeWithoutResult(status ->
                            jdbcClient.sql(TRY_LOCK).param(userId).query(Integer.class).list());
                    return false;
                } catch (final DataAccessException lockNotAvailable) {
                    return true;
                }
            }).get(PROBE_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        } catch (final InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        } catch (final ExecutionException | TimeoutException e) {
            throw new IllegalStateException(e);
        }
    }
}
