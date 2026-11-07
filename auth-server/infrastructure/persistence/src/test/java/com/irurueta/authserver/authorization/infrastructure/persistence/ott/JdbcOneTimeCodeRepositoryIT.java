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

package com.irurueta.authserver.authorization.infrastructure.persistence.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.ott.OneTimeCode;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.Executors;
import java.util.stream.IntStream;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Integration tests of {@link JdbcOneTimeCodeRepository} against PostgreSQL with the real migrations.
 */
class JdbcOneTimeCodeRepositoryIT {

    /** Current instant used by the tests, truncated to what the database stores. */
    private static final Instant NOW = Instant.now().truncatedTo(ChronoUnit.MILLIS);

    /** Lifetime of the codes. */
    private static final Duration LIFETIME = Duration.ofMinutes(10);

    /** Number of concurrent threads in the atomicity tests. */
    private static final int THREADS = 8;

    /** Binding of the codes. */
    private static final String BINDING = "binding-a";

    /** User name of the codes. */
    private static final String USERNAME = "user-a";

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Repository under test. */
    private static JdbcOneTimeCodeRepository repository;

    /**
     * Connects to the migrated database and builds the repository.
     */
    @BeforeAll
    static void connect() {
        jdbcClient = JdbcClient.create(MigratedPostgres.dataSource());
        repository = new JdbcOneTimeCodeRepository(jdbcClient, new OneTimeCodeRowMapper());
    }

    /**
     * Removes the data of the previous test.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM ott_codes").update();
    }

    /**
     * Verifies that a saved code is found with every field.
     */
    @Test
    void findActive_whenCodeIsSaved_returnsIt() {
        final var code = code(BINDING, USERNAME, NOW.plus(LIFETIME));
        repository.save(code);

        assertEquals(code, repository.findActive(BINDING, USERNAME, NOW).orElseThrow());
    }

    /**
     * Verifies that saving replaces the code of the same binding and user only.
     */
    @Test
    void save_whenSameBindingAndUser_replacesPreviousCode() {
        final var first = code(BINDING, USERNAME, NOW.plus(LIFETIME));
        final var other = code("binding-b", USERNAME, NOW.plus(LIFETIME));
        final var second = code(BINDING, USERNAME, NOW.plus(LIFETIME));
        repository.save(first);
        repository.save(other);

        repository.save(second);

        assertEquals(second, repository.findActive(BINDING, USERNAME, NOW).orElseThrow());
        assertEquals(other, repository.findActive("binding-b", USERNAME, NOW).orElseThrow());
        assertFalse(repository.consume(first.id()));
    }

    /**
     * Verifies that an expired or unknown code is not active.
     */
    @Test
    void findActive_whenCodeIsExpiredOrUnknown_returnsEmpty() {
        final var code = code(BINDING, USERNAME, NOW.plus(LIFETIME));
        repository.save(code);

        assertTrue(repository.findActive(BINDING, USERNAME, code.expiresAt()).isEmpty());
        assertTrue(repository.findActive("other", USERNAME, NOW).isEmpty());
        assertTrue(repository.findActive(BINDING, "other", NOW).isEmpty());
    }

    /**
     * Verifies that attempts are counted and an unknown code reports zero.
     */
    @Test
    void incrementAttempts_whenCalled_countsAttempts() {
        final var code = code(BINDING, USERNAME, NOW.plus(LIFETIME));
        repository.save(code);

        assertEquals(1, repository.incrementAttempts(code.id()));
        assertEquals(2, repository.incrementAttempts(code.id()));
        assertEquals(2, repository.findActive(BINDING, USERNAME, NOW).orElseThrow().attempts());
        assertEquals(0, repository.incrementAttempts(UUID.randomUUID()));
    }

    /**
     * Verifies that concurrent increments never lose an update.
     *
     * @throws Exception if a worker fails.
     */
    @Test
    void incrementAttempts_whenConcurrent_neverLosesAnIncrement() throws Exception {
        final var code = code(BINDING, USERNAME, NOW.plus(LIFETIME));
        repository.save(code);

        final var results = runConcurrently(() -> repository.incrementAttempts(code.id()));

        assertEquals(THREADS, repository.findActive(BINDING, USERNAME, NOW).orElseThrow().attempts());
        assertEquals(THREADS, results.stream().distinct().count());
    }

    /**
     * Verifies that a code is spent once only, also under concurrency.
     *
     * @throws Exception if a worker fails.
     */
    @Test
    void consume_whenConcurrent_succeedsExactlyOnce() throws Exception {
        final var code = code(BINDING, USERNAME, NOW.plus(LIFETIME));
        repository.save(code);

        final var results = runConcurrently(() -> repository.consume(code.id()) ? 1 : 0);

        assertEquals(1, results.stream().filter(result -> result == 1).count());
        assertFalse(repository.consume(code.id()));
        assertTrue(repository.findActive(BINDING, USERNAME, NOW).isEmpty());
    }

    /**
     * Verifies that only expired codes are deleted.
     */
    @Test
    void deleteExpired_whenSomeCodesExpired_deletesOnlyThose() {
        final var expired = code("binding-b", USERNAME, NOW.minusSeconds(1), NOW.minus(LIFETIME));
        final var live = code(BINDING, USERNAME, NOW.plus(LIFETIME));
        repository.save(expired);
        repository.save(live);

        assertEquals(1, repository.deleteExpired(NOW));

        assertEquals(live, repository.findActive(BINDING, USERNAME, NOW).orElseThrow());
        assertFalse(repository.consume(expired.id()));
    }

    /**
     * Runs the same action on several threads at once.
     *
     * @param action action returning a number.
     * @return the results of every thread.
     * @throws Exception if a worker fails.
     */
    private List<Integer> runConcurrently(final Callable<Integer> action) throws Exception {
        final var executor = Executors.newFixedThreadPool(THREADS);
        try {
            final var futures = IntStream.range(0, THREADS).mapToObj(i -> executor.submit(action)).toList();
            final var results = new ArrayList<Integer>();
            for (final var future : futures) {
                results.add(future.get());
            }
            return results;
        } finally {
            executor.shutdownNow();
        }
    }

    /**
     * Builds a code created now.
     *
     * @param bindingId binding of the code.
     * @param username  user name of the code.
     * @param expiresAt expiry instant.
     * @return the code.
     */
    private OneTimeCode code(final String bindingId, final String username, final Instant expiresAt) {
        return code(bindingId, username, expiresAt, NOW);
    }

    /**
     * Builds a code.
     *
     * @param bindingId bindingId of the code.
     * @param username  user name of the code.
     * @param expiresAt expiry instant.
     * @param createdAt creation instant.
     * @return the code.
     */
    private OneTimeCode code(final String bindingId, final String username, final Instant expiresAt,
                             final Instant createdAt) {
        return new OneTimeCode(UUID.randomUUID(), username, OttChannel.EMAIL, OttPurpose.LOGIN, "hash",
                bindingId, 0, expiresAt, createdAt);
    }
}
