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

package com.irurueta.authserver.authorization.infrastructure.persistence.totp;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.totp.RecoveryCode;
import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Integration tests of {@link JdbcRecoveryCodeRepository} against PostgreSQL. No Spring context is needed.
 */
class JdbcRecoveryCodeRepositoryIT {

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Repository under test. */
    private static JdbcRecoveryCodeRepository repository;

    /** Identifier of the user that owns the codes. */
    private UUID userId;

    /**
     * Connects to the migrated database and builds the repository.
     */
    @BeforeAll
    static void connect() {
        jdbcClient = JdbcClient.create(MigratedPostgres.dataSource());
        repository = new JdbcRecoveryCodeRepository(jdbcClient, new RecoveryCodeRowMapper());
    }

    /**
     * Removes the data of the previous test and inserts the user that owns the codes.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM users").update();
        userId = UUID.randomUUID();
        jdbcClient.sql("INSERT INTO users (id, username) VALUES (?, ?)").params(userId, "user-" + userId).update();
    }

    /**
     * Verifies that replacing stores the new codes and drops the previous ones.
     */
    @Test
    void replaceAll_whenCodesExist_replacesThem() {
        repository.replaceAll(userId, List.of(code("old-1"), code("old-2")));
        final var fresh = code("new-1");

        repository.replaceAll(userId, List.of(fresh));

        assertEquals(List.of(fresh), repository.findUnused(userId));
    }

    /**
     * Verifies that only unused codes are listed, and only those of the user.
     */
    @Test
    void findUnused_whenSomeCodesAreSpent_listsOnlyUnusedOnes() {
        final var kept = code("kept");
        final var spent = code("spent");
        repository.replaceAll(userId, List.of(kept, spent));
        repository.markUsed(spent.id(), Instant.now());

        assertEquals(List.of(kept), repository.findUnused(userId));
        assertTrue(repository.findUnused(UUID.randomUUID()).isEmpty());
    }

    /**
     * Verifies that a code can be spent once only.
     */
    @Test
    void markUsed_whenCodeIsSpentTwice_succeedsOnlyOnce() {
        final var code = code("once");
        repository.replaceAll(userId, List.of(code));

        assertTrue(repository.markUsed(code.id(), Instant.now()));
        assertFalse(repository.markUsed(code.id(), Instant.now()));
        assertFalse(repository.markUsed(UUID.randomUUID(), Instant.now()));
    }

    /**
     * Verifies that deleting removes every code of the user.
     */
    @Test
    void deleteByUser_whenCodesExist_removesThem() {
        repository.replaceAll(userId, List.of(code("a"), code("b")));

        repository.deleteByUser(userId);

        assertTrue(repository.findUnused(userId).isEmpty());
    }

    /**
     * Builds an unused code of the user.
     *
     * @param hash hash of the code.
     * @return the code.
     */
    private RecoveryCode code(final String hash) {
        return new RecoveryCode(UUID.randomUUID(), userId, hash, null);
    }
}
