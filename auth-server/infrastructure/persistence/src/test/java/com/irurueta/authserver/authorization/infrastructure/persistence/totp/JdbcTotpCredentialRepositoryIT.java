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
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.totp.TotpCredential;
import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Integration tests of {@link JdbcTotpCredentialRepository} against PostgreSQL. No Spring context is needed.
 */
class JdbcTotpCredentialRepositoryIT {

    /** Step used by the tests. */
    private static final long STEP = 100L;

    /** Secret used by the tests. */
    private static final byte[] SECRET = {1, 2, 4};

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Repository under test. */
    private static JdbcTotpCredentialRepository repository;

    /** Identifier of the user that owns the credential. */
    private UUID userId;

    /**
     * Connects to the migrated database and builds the repository.
     */
    @BeforeAll
    static void connect() {
        jdbcClient = JdbcClient.create(MigratedPostgres.dataSource());
        repository = new JdbcTotpCredentialRepository(jdbcClient, new TotpCredentialRowMapper());
    }

    /**
     * Removes the data of the previous test and inserts the user that owns the credential.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM users").update();
        userId = UUID.randomUUID();
        jdbcClient.sql("INSERT INTO users (id, username) VALUES (?, ?)").params(userId, "user-" + userId).update();
    }

    /**
     * Verifies that a saved credential is found with every field intact, and that an unknown user has none.
     */
    @Test
    void save_whenCredentialIsNew_isFoundByUser() {
        final var credential = credential(SECRET, false, TotpCredential.NEVER_USED);

        repository.save(credential);

        final var found = repository.findByUser(userId).orElseThrow();
        assertEquals(credential, found);
        assertArrayEquals(SECRET, found.encryptedSecret());
        assertTrue(repository.findByUser(UUID.randomUUID()).isEmpty());
    }

    /**
     * Verifies that saving again replaces the previous credential of the user.
     */
    @Test
    void save_whenCredentialExists_replacesIt() {
        repository.save(credential(new byte[] {1}, true, STEP));
        final var replacement = credential(new byte[] {9, 8}, false, TotpCredential.NEVER_USED);

        repository.save(replacement);

        assertEquals(replacement, repository.findByUser(userId).orElseThrow());
    }

    /**
     * Verifies that confirming flips the flag.
     */
    @Test
    void confirm_whenCredentialIsPending_marksItConfirmed() {
        repository.save(credential(new byte[] {1}, false, TotpCredential.NEVER_USED));

        repository.confirm(userId);

        assertTrue(repository.findByUser(userId).orElseThrow().confirmed());
    }

    /**
     * Verifies that a step is accepted only when newer than the stored one, so a code cannot be replayed.
     */
    @Test
    void advanceLastUsedStep_whenStepIsReplayed_returnsFalse() {
        repository.save(credential(new byte[] {1}, true, TotpCredential.NEVER_USED));

        assertTrue(repository.advanceLastUsedStep(userId, STEP));
        assertFalse(repository.advanceLastUsedStep(userId, STEP));
        assertFalse(repository.advanceLastUsedStep(userId, STEP - 1));
        assertTrue(repository.advanceLastUsedStep(userId, STEP + 1));
        assertEquals(STEP + 1, repository.findByUser(userId).orElseThrow().lastUsedStep());
    }

    /**
     * Verifies that no step is accepted for a user without credential.
     */
    @Test
    void advanceLastUsedStep_whenUserHasNoCredential_returnsFalse() {
        assertFalse(repository.advanceLastUsedStep(userId, STEP));
    }

    /**
     * Verifies that deleting removes the credential, and that deleting the user cascades.
     */
    @Test
    void deleteByUser_whenCredentialExists_removesIt() {
        repository.save(credential(new byte[] {1}, true, STEP));

        repository.deleteByUser(userId);

        assertTrue(repository.findByUser(userId).isEmpty());
    }

    /**
     * Verifies that deleting the user deletes its credential.
     */
    @Test
    void save_whenUserIsDeleted_cascadesToTheCredential() {
        repository.save(credential(new byte[] {1}, true, STEP));

        jdbcClient.sql("DELETE FROM users WHERE id = ?").param(userId).update();

        assertTrue(repository.findByUser(userId).isEmpty());
    }

    /**
     * Builds a credential of the user.
     *
     * @param secret    encrypted secret.
     * @param confirmed whether it is confirmed.
     * @param step      last used step.
     * @return the credential.
     */
    private TotpCredential credential(final byte[] secret, final boolean confirmed, final long step) {
        return new TotpCredential(userId, secret, confirmed, step, Instant.now().truncatedTo(ChronoUnit.MILLIS));
    }
}
