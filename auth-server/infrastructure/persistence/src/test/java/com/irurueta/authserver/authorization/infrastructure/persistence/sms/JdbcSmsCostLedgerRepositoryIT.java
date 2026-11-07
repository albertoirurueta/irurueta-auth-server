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

import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Integration tests of {@link JdbcSmsCostLedgerRepository} against PostgreSQL with the real migrations.
 */
class JdbcSmsCostLedgerRepositoryIT {

    /** Instant used by the tests, truncated to what the database stores. */
    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.MILLIS);

    /** Window of the budget. */
    private static final Duration WINDOW = Duration.ofHours(24);

    /** Cost of a message, in millionths of the currency unit. */
    private static final long COST = 7_000L;

    /** Cost of another message. */
    private static final long OTHER_COST = 3_000L;

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Repository under test. */
    private static JdbcSmsCostLedgerRepository repository;

    /**
     * Connects to the migrated database and builds the repository.
     */
    @BeforeAll
    static void connect() {
        jdbcClient = JdbcClient.create(MigratedPostgres.dataSource());
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
     * Verifies that the first row is the whole spend.
     */
    @Test
    void recordAndGetSpend_whenLedgerIsEmpty_returnsCostOfNewRow() {
        assertEquals(COST, repository.recordAndGetSpend(NOW, "ES", COST, WINDOW));
    }

    /**
     * Verifies that rows of the window add up, including the new one.
     */
    @Test
    void recordAndGetSpend_whenRowsInWindow_sumsThem() {
        repository.recordAndGetSpend(NOW.minus(Duration.ofHours(1)), "ES", COST, WINDOW);

        assertEquals(COST + OTHER_COST, repository.recordAndGetSpend(NOW, "FR", OTHER_COST, WINDOW));
    }

    /**
     * Verifies that rows older than the window are not summed.
     */
    @Test
    void recordAndGetSpend_whenRowIsOutsideWindow_ignoresIt() {
        repository.recordAndGetSpend(NOW.minus(WINDOW).minusSeconds(1), "ES", COST, WINDOW);
        repository.recordAndGetSpend(NOW.minus(WINDOW), "ES", COST, WINDOW);

        assertEquals(OTHER_COST, repository.recordAndGetSpend(NOW, "ES", OTHER_COST, WINDOW));
    }

    /**
     * Verifies that only rows older than the instant are deleted.
     */
    @Test
    void deleteOlderThan_whenSomeRowsAreOld_deletesOnlyThose() {
        repository.recordAndGetSpend(NOW.minus(Duration.ofDays(2)), "ES", COST, WINDOW);
        repository.recordAndGetSpend(NOW, "ES", OTHER_COST, WINDOW);

        assertEquals(1, repository.deleteOlderThan(NOW.minus(Duration.ofDays(1))));

        assertEquals(OTHER_COST + COST, repository.recordAndGetSpend(NOW, "ES", COST, WINDOW));
    }
}
