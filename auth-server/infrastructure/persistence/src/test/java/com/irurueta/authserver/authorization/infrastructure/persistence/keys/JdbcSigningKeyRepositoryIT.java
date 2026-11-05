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

package com.irurueta.authserver.authorization.infrastructure.persistence.keys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.keys.SigningKey;
import com.irurueta.authserver.authorization.domain.keys.SigningKeyStatus;
import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Integration tests of {@link JdbcSigningKeyRepository} against PostgreSQL. No Spring context is needed.
 */
class JdbcSigningKeyRepositoryIT {

    /** Timeout, in seconds, when waiting for concurrent work. */
    private static final long TIMEOUT_SECONDS = 20;

    /** Time, in milliseconds, the first holder keeps the lock. */
    private static final long HOLD_MILLIS = 500;

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Repository under test. */
    private static JdbcSigningKeyRepository repository;

    /**
     * Connects to the migrated database and builds the repository.
     */
    @BeforeAll
    static void connect() {
        final var dataSource = MigratedPostgres.dataSource();
        jdbcClient = JdbcClient.create(dataSource);
        repository = new JdbcSigningKeyRepository(jdbcClient,
                new TransactionTemplate(new DataSourceTransactionManager(dataSource)), new SigningKeyRowMapper());
    }

    /**
     * Removes the keys of the previous test.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM signing_keys").update();
    }

    /**
     * Verifies that a saved key is read back with all its fields, and that saving again updates its state.
     */
    @Test
    void save_whenKeyIsSavedTwice_updatesItsState() {
        final var created = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        final var key = key(SigningKeyStatus.NEXT, created);

        repository.save(key);
        repository.save(key.activate(created.plusSeconds(1)));

        final var keys = repository.findAll();
        assertEquals(1, keys.size());
        assertEquals(SigningKeyStatus.ACTIVE, keys.getFirst().status());
        assertEquals(created.plusSeconds(1), keys.getFirst().activatedAt());
        assertEquals(key.publicJwk(), keys.getFirst().publicJwk());
    }

    /**
     * Verifies that two active keys cannot coexist.
     */
    @Test
    void save_whenTwoKeysAreActive_isRejected() {
        final var now = Instant.now();
        repository.save(key(SigningKeyStatus.ACTIVE, now));
        final var second = key(SigningKeyStatus.ACTIVE, now);

        assertThrows(DuplicateKeyException.class, () -> repository.save(second));
    }

    /**
     * Verifies that a key is deleted by its identifier.
     */
    @Test
    void deleteByKid_whenKeyExists_removesIt() {
        final var key = key(SigningKeyStatus.RETIRED, Instant.now());
        repository.save(key);

        repository.deleteByKid(key.kid());

        assertTrue(repository.findAll().isEmpty());
    }

    /**
     * Verifies that two rotations do not run at the same time.
     *
     * @throws Exception if the concurrent work is interrupted.
     */
    @Test
    void withRotationLock_whenCalledConcurrently_serialisesTheActions() throws Exception {
        final var inside = new AtomicBoolean();
        final var overlapped = new AtomicBoolean();
        final var entered = new CountDownLatch(1);
        final var action = (Supplier<Boolean>) () -> {
            if (!inside.compareAndSet(false, true)) {
                overlapped.set(true);
            }
            entered.countDown();
            try {
                Thread.sleep(HOLD_MILLIS);
            } catch (final InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            inside.set(false);
            return true;
        };
        final var executor = Executors.newFixedThreadPool(2);
        try {
            final var first = executor.submit(() -> repository.withRotationLock(action));
            assertTrue(entered.await(TIMEOUT_SECONDS, TimeUnit.SECONDS));
            final var second = executor.submit(() -> repository.withRotationLock(action));

            assertTrue(first.get(TIMEOUT_SECONDS, TimeUnit.SECONDS));
            assertTrue(second.get(TIMEOUT_SECONDS, TimeUnit.SECONDS));
        } finally {
            executor.shutdownNow();
        }
        assertFalse(overlapped.get());
    }

    /**
     * Builds a key with a random identifier.
     *
     * @param status  lifecycle state.
     * @param created creation instant.
     * @return the key.
     */
    private static SigningKey key(final SigningKeyStatus status, final Instant created) {
        final var kid = UUID.randomUUID().toString();
        final var activated = status == SigningKeyStatus.NEXT ? null : created;
        return new SigningKey(kid, "RS256", "{\"kid\":\"" + kid + "\"}", "encrypted-" + kid, status, created,
                activated, null);
    }
}
