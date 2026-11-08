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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Integration tests of {@link JdbcClientAssertionReplayRegistry} against a migrated PostgreSQL.
 */
class JdbcClientAssertionReplayRegistryIT {

    /** Client identifier. */
    private static final String CLIENT_ID = "client-a";

    /** Another client identifier. */
    private static final String OTHER_CLIENT_ID = "client-b";

    /** Assertion identifier. */
    private static final String JTI = "jti-1";

    /** Number of simultaneous registrations of the same identifier. */
    private static final int CONCURRENT = 8;

    /** Longest wait for the concurrent registrations, in seconds. */
    private static final long TIMEOUT_SECONDS = 30L;

    /** Lifetime of a registered assertion, in minutes. */
    private static final long LIFETIME_MINUTES = 5L;

    /** Count of rows. */
    private static final String COUNT = "SELECT count(*) FROM client_assertion_jtis";

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Registry under test. */
    private static JdbcClientAssertionReplayRegistry registry;

    /**
     * Connects to the migrated database and builds the registry.
     */
    @BeforeAll
    static void connect() {
        jdbcClient = JdbcClient.create(MigratedPostgres.dataSource());
        registry = new JdbcClientAssertionReplayRegistry(jdbcClient);
    }

    /**
     * Removes the rows of the previous test.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM client_assertion_jtis").update();
    }

    /**
     * Verifies that the first registration wins and a repetition is a replay.
     */
    @Test
    void register_whenSamePairRegisteredTwice_secondIsReplay() {
        final var expiresAt = Instant.now().plus(LIFETIME_MINUTES, ChronoUnit.MINUTES);

        assertTrue(registry.register(CLIENT_ID, JTI, expiresAt));
        assertFalse(registry.register(CLIENT_ID, JTI, expiresAt));
    }

    /**
     * Verifies that the same identifier of two clients is not a replay.
     */
    @Test
    void register_whenSameJtiOfAnotherClient_isFirstUse() {
        final var expiresAt = Instant.now().plus(LIFETIME_MINUTES, ChronoUnit.MINUTES);

        assertTrue(registry.register(CLIENT_ID, JTI, expiresAt));
        assertTrue(registry.register(OTHER_CLIENT_ID, JTI, expiresAt));
    }

    /**
     * Verifies that of several concurrent registrations of the same identifier exactly one wins.
     *
     * @throws InterruptedException if the wait is interrupted.
     * @throws ExecutionException   if a registration fails.
     * @throws TimeoutException     if the registrations do not finish in time.
     */
    @Test
    void register_whenSameJtiRegisteredConcurrently_exactlyOneWins()
            throws InterruptedException, ExecutionException, TimeoutException {
        final var expiresAt = Instant.now().plus(LIFETIME_MINUTES, ChronoUnit.MINUTES);
        final var start = new CountDownLatch(1);
        final var executor = Executors.newFixedThreadPool(CONCURRENT);
        try {
            final var futures = new ArrayList<Future<Boolean>>();
            for (var i = 0; i < CONCURRENT; i++) {
                futures.add(executor.submit(() -> {
                    start.await();
                    return registry.register(CLIENT_ID, JTI, expiresAt);
                }));
            }
            start.countDown();
            var winners = 0;
            for (final var future : futures) {
                if (future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                    winners++;
                }
            }

            assertEquals(1, winners);
            assertEquals(1, jdbcClient.sql(COUNT).query(Integer.class).single());
        } finally {
            executor.shutdownNow();
        }
    }

    /**
     * Verifies that only the expired identifiers are purged.
     */
    @Test
    void purgeExpired_whenSomeExpired_removesOnlyThose() {
        final var now = Instant.now();
        registry.register(CLIENT_ID, "old", now.minus(1, ChronoUnit.MINUTES));
        registry.register(CLIENT_ID, "edge", now);
        registry.register(CLIENT_ID, "live", now.plus(1, ChronoUnit.MINUTES));

        assertEquals(2, registry.purgeExpired(now));
        assertEquals(1, jdbcClient.sql(COUNT).query(Integer.class).single());
        assertFalse(registry.register(CLIENT_ID, "live", now.plus(1, ChronoUnit.MINUTES)));
        assertTrue(registry.register(CLIENT_ID, "old", now.plus(1, ChronoUnit.MINUTES)));
    }
}
