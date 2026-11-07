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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import java.nio.charset.StandardCharsets;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutableCredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCose;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.management.JdbcUserCredentialRepository;

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

    /** Instant the credential saved by the framework was last used, with the microseconds PostgreSQL keeps. */
    private static final Instant LATEST = Instant.parse("2026-01-03T10:00:00.123456Z");

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Repository under test. */
    private static JdbcPasskeyRepository repository;

    /** Spring Security's own credential store, which writes and reads the same table. */
    private static JdbcUserCredentialRepository frameworkRepository;

    /**
     * Connects to the migrated database and builds the repository.
     */
    @BeforeAll
    static void connect() {
        jdbcClient = JdbcClient.create(MigratedPostgres.dataSource());
        repository = new JdbcPasskeyRepository(jdbcClient, new PasskeyRowMapper());
        frameworkRepository = new JdbcUserCredentialRepository(new JdbcTemplate(MigratedPostgres.dataSource()));
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
     * Verifies that a passkey is deleted only through its owner.
     */
    @Test
    void delete_whenPasskeyBelongsToAnotherUser_changesNothing() {
        assertFalse(repository.delete("older", BOB));
        assertEquals(2, repository.findByUserId(ALICE).size());

        assertTrue(repository.delete("older", ALICE));
        assertEquals(1, repository.findByUserId(ALICE).size());
    }

    /**
     * Verifies that an account is found to have passkeys through its {@code users} row in a single query, and that
     * an account without passkeys, one whose passkeys were deleted and an unknown account are not.
     */
    @Test
    void existsForAccount_whenAccountHasPasskeys_returnsTrue() {
        final var suffix = UUID.randomUUID().toString();
        final var withPasskey = insertUser("passkey-" + suffix);
        final var withoutPasskey = insertUser("plain-" + suffix);
        final var handle = "handle-" + suffix;
        jdbcClient.sql("INSERT INTO user_entities (id, name, display_name) VALUES (?, ?, ?)")
                .params(handle, "passkey-" + suffix, "Passkey").update();
        insertCredential("cred-" + suffix, handle, "Key", OLDER, null);

        assertTrue(repository.existsForAccount(withPasskey));
        assertFalse(repository.existsForAccount(withoutPasskey));
        assertFalse(repository.existsForAccount(UUID.randomUUID()));

        assertTrue(repository.delete("cred-" + suffix, handle));
        assertFalse(repository.existsForAccount(withPasskey));
    }

    /**
     * Verifies that two user entities can never share an account name, so the lookup by name has one answer.
     */
    @Test
    void userEntities_whenNameIsRepeated_isRejected() {
        final var duplicate = jdbcClient.sql("INSERT INTO user_entities (id, name, display_name) VALUES (?, ?, ?)")
                .params("another-handle", "alice", "Alice again");

        assertThrows(DuplicateKeyException.class, duplicate::update);
    }

    /**
     * Verifies that Spring Security's own credential store still writes and reads the creation and last use of a
     * credential, now that both columns are {@code timestamp with time zone}, and that this repository reads the same
     * instants back, after an insert and after the update the framework makes on every sign-in.
     */
    @Test
    void frameworkRepository_whenCredentialIsSavedAndUpdated_roundTripsTheInstants() {
        final var credentialId = Bytes.random();
        final var record = ImmutableCredentialRecord.builder()
                .credentialType(PublicKeyCredentialType.PUBLIC_KEY)
                .credentialId(credentialId)
                .userEntityUserId(Bytes.fromBase64(ALICE))
                .publicKey(new ImmutablePublicKeyCose("public-key".getBytes(StandardCharsets.UTF_8)))
                .signatureCount(COUNTER)
                .uvInitialized(true)
                .transports(Set.of(AuthenticatorTransport.INTERNAL))
                .backupEligible(true)
                .backupState(false)
                .created(OLDER)
                .lastUsed(NEWER)
                .label("Framework key")
                .build();

        frameworkRepository.save(record);

        final var saved = frameworkRepository.findByCredentialId(credentialId);
        assertNotNull(saved);
        assertEquals(OLDER, saved.getCreated());
        assertEquals(NEWER, saved.getLastUsed());
        final var passkey = repository.findByIdAndUserId(credentialId.toBase64UrlString(), ALICE).orElseThrow();
        assertEquals(OLDER, passkey.createdAt());
        assertEquals(NEWER, passkey.lastUsedAt());

        frameworkRepository.save(ImmutableCredentialRecord.fromCredentialRecord(record).lastUsed(LATEST).build());

        final var updated = frameworkRepository.findByCredentialId(credentialId);
        assertNotNull(updated);
        assertEquals(LATEST, updated.getLastUsed());
        assertEquals(LATEST,
                repository.findByIdAndUserId(credentialId.toBase64UrlString(), ALICE).orElseThrow().lastUsedAt());
    }

    /**
     * Inserts an account.
     *
     * @param username name of the account.
     * @return identifier of the account.
     */
    private static UUID insertUser(final String username) {
        final var id = UUID.randomUUID();
        jdbcClient.sql("INSERT INTO users (id, username) VALUES (?, ?)").params(id, username).update();
        return id;
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
