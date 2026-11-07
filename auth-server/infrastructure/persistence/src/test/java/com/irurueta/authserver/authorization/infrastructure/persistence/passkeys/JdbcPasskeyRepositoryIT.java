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

package com.irurueta.authserver.authorization.infrastructure.persistence.passkeys;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import java.sql.Timestamp;
import java.time.Instant;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Integration tests of {@link JdbcPasskeyRepository} against PostgreSQL, on the schema of the {@code V500} migration.
 * No Spring context is needed.
 */
class JdbcPasskeyRepositoryIT {

    /** User handle of the first account. */
    private static final String ALICE = "alice-handle";

    /** User handle of the second account. */
    private static final String BOB = "bob-handle";

    /** Signature counter of the stored credentials. */
    private static final long COUNTER = 5L;

    /** Instant the older credential was created. */
    private static final Instant OLDER = Instant.parse("2026-01-01T10:00:00Z");

    /** Instant the newer credential was created. */
    private static final Instant NEWER = Instant.parse("2026-01-02T10:00:00Z");

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Repository under test. */
    private static JdbcPasskeyRepository repository;

    /**
     * Connects to the migrated database and builds the repository.
     */
    @BeforeAll
    static void connect() {
        jdbcClient = JdbcClient.create(MigratedPostgres.dataSource());
        repository = new JdbcPasskeyRepository(jdbcClient, new PasskeyRowMapper());
    }

    /**
     * Removes the data of the previous test and inserts two accounts, the first with two passkeys.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM user_credentials").update();
        jdbcClient.sql("DELETE FROM user_entities").update();
        jdbcClient.sql("INSERT INTO user_entities (id, name, display_name) VALUES (?, ?, ?)")
                .params(ALICE, "alice", "Alice").update();
        jdbcClient.sql("INSERT INTO user_entities (id, name, display_name) VALUES (?, ?, ?)")
                .params(BOB, "bob", "Bob").update();
        insertCredential("newer", ALICE, "Phone", NEWER, null);
        insertCredential("older", ALICE, "Laptop", OLDER, NEWER);
        insertCredential("bobs", BOB, "Bob key", OLDER, null);
    }

    /**
     * Verifies that the user handle is found by account name, and an unknown account has none.
     */
    @Test
    void findUserIdByUsername_whenAccountHasAnEntity_returnsHandle() {
        assertEquals(ALICE, repository.findUserIdByUsername("alice").orElseThrow());
        assertTrue(repository.findUserIdByUsername("carol").isEmpty());
    }

    /**
     * Verifies that the passkeys of a user come oldest first with every field mapped, and without those of others.
     */
    @Test
    void findByUserId_whenUserHasPasskeys_returnsThemOldestFirst() {
        final var passkeys = repository.findByUserId(ALICE);

        assertEquals(2, passkeys.size());
        final var first = passkeys.getFirst();
        assertEquals("older", first.id());
        assertEquals(ALICE, first.userId());
        assertEquals("Laptop", first.label());
        assertEquals(OLDER, first.createdAt());
        assertEquals(NEWER, first.lastUsedAt());
        assertEquals(COUNTER, first.signatureCount());
        assertTrue(first.backupEligible());
        assertFalse(first.backedUp());
        assertEquals("newer", passkeys.getLast().id());
        assertNull(passkeys.getLast().lastUsedAt());
        assertTrue(repository.findByUserId("nobody").isEmpty());
    }

    /**
     * Verifies that a passkey is only found through its owner.
     */
    @Test
    void findByIdAndUserId_whenPasskeyBelongsToAnotherUser_returnsEmpty() {
        assertEquals("Laptop", repository.findByIdAndUserId("older", ALICE).orElseThrow().label());
        assertTrue(repository.findByIdAndUserId("older", BOB).isEmpty());
        assertTrue(repository.findByIdAndUserId("missing", ALICE).isEmpty());
    }

    /**
     * Verifies that a passkey is renamed only through its owner.
     */
    @Test
    void rename_whenPasskeyBelongsToAnotherUser_changesNothing() {
        assertFalse(repository.rename("older", BOB, "Stolen"));
        assertEquals("Laptop", repository.findByIdAndUserId("older", ALICE).orElseThrow().label());

        assertTrue(repository.rename("older", ALICE, "Work laptop"));
        assertEquals("Work laptop", repository.findByIdAndUserId("older", ALICE).orElseThrow().label());
    }

    /**
     * Verifies that a passkey is deleted only through its owner, and the count follows.
     */
    @Test
    void delete_whenPasskeyBelongsToAnotherUser_changesNothing() {
        assertFalse(repository.delete("older", BOB));
        assertEquals(2L, repository.countByUserId(ALICE));

        assertTrue(repository.delete("older", ALICE));
        assertEquals(1L, repository.countByUserId(ALICE));
        assertEquals(0L, repository.countByUserId("nobody"));
    }

    /**
     * Inserts a credential with the columns Spring Security's repository would fill.
     *
     * @param id       credential identifier.
     * @param userId   user handle of the owner.
     * @param label    label of the credential.
     * @param created  creation instant.
     * @param lastUsed last use, or {@code null}.
     */
    private static void insertCredential(
            final String id, final String userId, final String label, final Instant created, final Instant lastUsed) {
        jdbcClient.sql("""
                INSERT INTO user_credentials (credential_id, user_entity_user_id, public_key, signature_count,
                    backup_eligible, backup_state, created, last_used, label)
                VALUES (?, ?, ?, ?, TRUE, FALSE, ?, ?, ?)
                """)
                .params(id, userId, new byte[] {1}, COUNTER, Timestamp.from(created),
                        lastUsed == null ? null : Timestamp.from(lastUsed), label)
                .update();
    }
}
