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
package com.irurueta.authserver.authorization.infrastructure.persistence.social;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Integration tests of {@link JdbcSignInMethodsLock} against PostgreSQL. No Spring context is needed.
 */
class JdbcSignInMethodsLockIT {

    /** Longest wait for the other connection, in seconds. */
    private static final long WAIT_SECONDS = 10;

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Runs a block in a transaction of the database. */
    private static TransactionTemplate transactions;

    /** Lock under test. */
    private static JdbcSignInMethodsLock lock;

    /**
     * Connects to the migrated database and builds the lock.
     */
    @BeforeAll
    static void connect() {
        jdbcClient = JdbcClient.create(MigratedPostgres.dataSource());
        transactions = new TransactionTemplate(new DataSourceTransactionManager(MigratedPostgres.dataSource()));
        lock = new JdbcSignInMethodsLock(jdbcClient);
    }

    /**
     * Verifies that the lock of an account is held until the transaction ends, and only for that account: another
     * connection cannot take it meanwhile but can take the lock of another account, and can take it once the
     * transaction is over.
     *
     * @throws Exception if the other connection fails or the wait is interrupted.
     */
    @Test
    void lock_whenInsideATransaction_holdsTheLockOfTheAccountUntilItEnds() throws Exception {
        final var userId = UUID.randomUUID();
        final var otherUserId = UUID.randomUUID();
        final var executor = Executors.newSingleThreadExecutor();
        try {
            final var observed = transactions.execute(status -> {
                lock.lock(userId);
                try {
                    final var same = executor.submit(() -> tryLock(userId)).get(WAIT_SECONDS, TimeUnit.SECONDS);
                    final var other = executor.submit(() -> tryLock(otherUserId)).get(WAIT_SECONDS, TimeUnit.SECONDS);
                    return new Boolean[] {same, other};
                } catch (final ExecutionException | TimeoutException e) {
                    throw new IllegalStateException(e);
                } catch (final InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException(e);
                }
            });

            assertEquals(Boolean.FALSE, observed[0]);
            assertEquals(Boolean.TRUE, observed[1]);
            assertTrue(executor.submit(() -> tryLock(userId)).get(WAIT_SECONDS, TimeUnit.SECONDS));
        } finally {
            executor.shutdownNow();
        }
    }

    /**
     * Tries to take the lock of an account from a connection outside any transaction of the test.
     *
     * @param userId identifier of the account.
     * @return whether the lock was free.
     */
    private static Boolean tryLock(final UUID userId) {
        return jdbcClient.sql("SELECT pg_try_advisory_xact_lock(?, hashtext(?))")
                .params(JdbcSignInMethodsLock.SIGN_IN_METHODS_LOCK_NAMESPACE, userId.toString())
                .query(Boolean.class).single();
    }
}
