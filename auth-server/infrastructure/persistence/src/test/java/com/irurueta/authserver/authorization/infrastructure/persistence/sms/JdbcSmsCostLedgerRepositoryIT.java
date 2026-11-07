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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.sms.SmsSpendCap;
import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Integration tests of {@link JdbcSmsCostLedgerRepository} against PostgreSQL with the real migrations.
 */
class JdbcSmsCostLedgerRepositoryIT {

    /** Instant used by the tests, truncated to what the database stores. */
    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.MILLIS);

    /** Short window of the budget. */
    private static final Duration WINDOW = Duration.ofHours(1);

    /** Window of the daily budget. */
    private static final Duration DAY = Duration.ofDays(1);

    /** Cost of a message, in millionths of the currency unit. */
    private static final long COST = 7_000L;

    /** Cost of another message. */
    private static final long OTHER_COST = 3_000L;

    /** A cap that nothing in the tests reaches. */
    private static final long LARGE_CAP = 1_000_000L;

    /** Number of messages the cap of the concurrency test pays for. */
    private static final int AFFORDABLE = 3;

    /** Number of concurrent senders of the concurrency test. */
    private static final int SENDERS = 12;

    /** Longest wait for the concurrent senders, in seconds. */
    private static final long WAIT_SECONDS = 60L;

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Runs the reservations in transactions, as the use cases do. */
    private static TransactionTemplate transactions;

    /** Repository under test. */
    private static JdbcSmsCostLedgerRepository repository;

    /**
     * Connects to the migrated database and builds the repository.
     */
    @BeforeAll
    static void connect() {
        jdbcClient = JdbcClient.create(MigratedPostgres.dataSource());
        transactions = new TransactionTemplate(new DataSourceTransactionManager(MigratedPostgres.dataSource()));
        repository = new JdbcSmsCostLedgerRepository(jdbcClient);
    }

    /**
     * Removes the data of the previous test.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM sms_cost_ledger").update();
    }

    /**
     * Verifies that a message within both caps is recorded.
     */
    @Test
    void tryRecord_whenWithinBothCaps_recordsTheMessage() {
        assertTrue(record(NOW, COST, LARGE_CAP, LARGE_CAP));

        assertEquals(COST, spend());
        assertEquals(1L, rows());
    }

    /**
     * Verifies that a message that exactly reaches the cap of the window is recorded, and the next one is refused
     * without leaving a row.
     */
    @Test
    void tryRecord_whenWindowCapWouldBeExceeded_refusesWithoutRecording() {
        assertTrue(record(NOW.minusSeconds(1), COST, COST + OTHER_COST, LARGE_CAP));
        assertTrue(record(NOW, OTHER_COST, COST + OTHER_COST, LARGE_CAP));

        assertFalse(record(NOW, 1L, COST + OTHER_COST, LARGE_CAP));

        assertEquals(2L, rows());
    }

    /**
     * Verifies that the daily cap refuses a message even when the short window is within its cap.
     */
    @Test
    void tryRecord_whenDailyCapWouldBeExceeded_refusesWithoutRecording() {
        assertTrue(record(NOW.minus(WINDOW).minusSeconds(1), COST, LARGE_CAP, COST));

        assertFalse(record(NOW, OTHER_COST, LARGE_CAP, COST));

        assertEquals(1L, rows());
    }

    /**
     * Verifies that rows older than a window are not counted against its cap.
     */
    @Test
    void tryRecord_whenRowIsOutsideTheWindows_ignoresIt() {
        assertTrue(record(NOW.minus(DAY), COST, COST, COST));

        assertTrue(record(NOW, COST, COST, COST));
    }

    /**
     * Verifies that concurrent senders, each in its own transaction, never overshoot the cap: exactly the messages it
     * pays for are recorded.
     *
     * @throws Exception if a sender fails or the wait is interrupted.
     */
    @Test
    void tryRecord_whenSendersAreConcurrent_neverOvershootsTheCap() throws Exception {
        final var cap = AFFORDABLE * COST;
        final var start = new CountDownLatch(1);
        final var executor = Executors.newFixedThreadPool(SENDERS);
        try {
            final var results = new ArrayList<Future<Boolean>>();
            for (var i = 0; i < SENDERS; i++) {
                final Callable<Boolean> sender = () -> {
                    start.await();
                    return record(NOW, COST, cap, LARGE_CAP);
                };
                results.add(executor.submit(sender));
            }
            start.countDown();
            var recorded = 0;
            for (final var result : results) {
                if (result.get(WAIT_SECONDS, TimeUnit.SECONDS)) {
                    recorded++;
                }
            }

            assertEquals(AFFORDABLE, recorded);
            assertEquals(cap, spend());
        } finally {
            executor.shutdownNow();
        }
    }

    /**
     * Verifies that only rows older than the instant are deleted.
     */
    @Test
    void deleteOlderThan_whenSomeRowsAreOld_deletesOnlyThose() {
        record(NOW.minus(Duration.ofDays(2)), COST, LARGE_CAP, LARGE_CAP);
        record(NOW, OTHER_COST, LARGE_CAP, LARGE_CAP);

        assertEquals(1, repository.deleteOlderThan(NOW.minus(Duration.ofDays(1))));

        assertEquals(OTHER_COST, spend());
    }

    /**
     * Tries to record a message in a transaction of its own, as the use case that sends an SMS does.
     *
     * @param sentAt     instant of the message.
     * @param cost       cost of the message.
     * @param windowCap  cap of the short window.
     * @param dailyCap   cap of the day.
     * @return whether the message was recorded.
     */
    private static boolean record(final Instant sentAt, final long cost, final long windowCap, final long dailyCap) {
        return Boolean.TRUE.equals(transactions.execute(status -> repository.tryRecord(sentAt, "ES", cost,
                new SmsSpendCap(WINDOW, windowCap), new SmsSpendCap(DAY, dailyCap))));
    }

    /**
     * Sums the recorded spend.
     *
     * @return the total cost of the rows.
     */
    private static long spend() {
        return jdbcClient.sql("SELECT COALESCE(SUM(cost_micros), 0)::bigint FROM sms_cost_ledger").query(Long.class)
                .single();
    }

    /**
     * Counts the recorded rows.
     *
     * @return the number of rows.
     */
    private static long rows() {
        return jdbcClient.sql("SELECT count(*) FROM sms_cost_ledger").query(Long.class).single();
    }
}
