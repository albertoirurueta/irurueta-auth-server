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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.social.FederatedIdentity;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Integration tests of {@link JdbcFederatedIdentityRepository} against PostgreSQL. No Spring context is needed.
 */
class JdbcFederatedIdentityRepositoryIT {

    /** Subject used by the tests. */
    private static final String SUBJECT = "subject-1";

    /** E-mail address used by the tests. */
    private static final String EMAIL = "alice@example.com";

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Repository under test. */
    private static JdbcFederatedIdentityRepository repository;

    /** Identifier of the user that owns the links. */
    private UUID userId;

    /**
     * Connects to the migrated database and builds the repository.
     */
    @BeforeAll
    static void connect() {
        jdbcClient = JdbcClient.create(MigratedPostgres.dataSource());
        repository = new JdbcFederatedIdentityRepository(jdbcClient, new FederatedIdentityRowMapper());
    }

    /**
     * Removes the data of the previous test and inserts the user that owns the links.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM users").update();
        userId = insertUser();
    }

    /**
     * Verifies that a stored link is found by its provider and subject, with every field round-tripped.
     */
    @Test
    void findByProviderAndSubject_whenLinked_returnsIt() {
        final var identity = identity(userId, IdentityProvider.GOOGLE, SUBJECT, null);
        repository.save(identity);

        assertEquals(identity, repository.findByProviderAndSubject(IdentityProvider.GOOGLE, SUBJECT).orElseThrow());
    }

    /**
     * Verifies that another provider or another subject is not found.
     */
    @Test
    void findByProviderAndSubject_whenNotLinked_returnsEmpty() {
        repository.save(identity(userId, IdentityProvider.GOOGLE, SUBJECT, null));

        assertTrue(repository.findByProviderAndSubject(IdentityProvider.GITHUB, SUBJECT).isEmpty());
        assertTrue(repository.findByProviderAndSubject(IdentityProvider.GOOGLE, "other").isEmpty());
    }

    /**
     * Verifies that saving a link again updates its e-mail address and last sign-in only.
     */
    @Test
    void save_whenLinkExists_updatesEmailAndLastLogin() {
        final var identity = identity(userId, IdentityProvider.GOOGLE, SUBJECT, null);
        repository.save(identity);
        final var lastLogin = Instant.now().truncatedTo(ChronoUnit.MILLIS);

        repository.save(new FederatedIdentity(identity.id(), userId, IdentityProvider.GOOGLE, SUBJECT,
                "new@example.com", identity.linkedAt().plusSeconds(1), lastLogin));

        final var stored = repository.findByIdAndUser(identity.id(), userId).orElseThrow();
        assertEquals("new@example.com", stored.email());
        assertEquals(lastLogin, stored.lastLoginAt());
        assertEquals(identity.linkedAt(), stored.linkedAt());
    }

    /**
     * Verifies that one external identity cannot be linked to two accounts.
     */
    @Test
    void save_whenIdentityIsLinkedToAnotherAccount_throwsDuplicateKeyException() {
        repository.save(identity(userId, IdentityProvider.GOOGLE, SUBJECT, null));
        final var other = identity(insertUser(), IdentityProvider.GOOGLE, SUBJECT, null);

        assertThrows(DuplicateKeyException.class, () -> repository.save(other));
    }

    /**
     * Verifies that the links of an account are listed oldest first, and only the account's own.
     */
    @Test
    void findByUser_whenAccountsHaveLinks_listsOnlyTheAccountsOldestFirst() {
        final var now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        final var older = new FederatedIdentity(UUID.randomUUID(), userId, IdentityProvider.GITHUB, "1", null,
                now.minusSeconds(10), null);
        final var newer = new FederatedIdentity(UUID.randomUUID(), userId, IdentityProvider.GOOGLE, "2", EMAIL, now,
                null);
        repository.save(newer);
        repository.save(older);
        repository.save(identity(insertUser(), IdentityProvider.APPLE, "3", null));

        assertEquals(List.of(older, newer), repository.findByUser(userId));
    }

    /**
     * Verifies that a link is reachable only by its owner.
     */
    @Test
    void findByIdAndUser_whenUserIsNotTheOwner_returnsEmpty() {
        final var identity = identity(userId, IdentityProvider.GOOGLE, SUBJECT, null);
        repository.save(identity);

        assertTrue(repository.findByIdAndUser(identity.id(), userId).isPresent());
        assertTrue(repository.findByIdAndUser(identity.id(), UUID.randomUUID()).isEmpty());
    }

    /**
     * Verifies that a link is deleted only by its owner.
     */
    @Test
    void delete_whenUserIsNotTheOwner_deletesOnlyForOwner() {
        final var identity = identity(userId, IdentityProvider.GOOGLE, SUBJECT, null);
        repository.save(identity);

        assertFalse(repository.delete(identity.id(), UUID.randomUUID()));
        assertTrue(repository.delete(identity.id(), userId));
        assertTrue(repository.findByUser(userId).isEmpty());
    }

    /**
     * Verifies that the links of an account are counted, and not the links of another one.
     */
    @Test
    void countByUser_whenAccountsHaveLinks_countsOnlyTheAccounts() {
        repository.save(identity(userId, IdentityProvider.GOOGLE, SUBJECT, null));
        repository.save(identity(userId, IdentityProvider.GITHUB, SUBJECT, null));
        repository.save(identity(insertUser(), IdentityProvider.APPLE, SUBJECT, null));

        assertEquals(2, repository.countByUser(userId));
    }

    /**
     * Verifies that the links disappear with their account.
     */
    @Test
    void delete_whenAccountIsDeleted_cascadesToItsLinks() {
        repository.save(identity(userId, IdentityProvider.GOOGLE, SUBJECT, null));

        jdbcClient.sql("DELETE FROM users WHERE id = ?").param(userId).update();

        assertEquals(0, repository.countByUser(userId));
    }

    /**
     * Inserts a user.
     *
     * @return identifier of the user.
     */
    private static UUID insertUser() {
        final var id = UUID.randomUUID();
        jdbcClient.sql("INSERT INTO users (id, username) VALUES (?, ?)").params(id, "user-" + id).update();
        return id;
    }

    /**
     * Builds a link.
     *
     * @param owner       account that owns the link.
     * @param provider    provider of the identity.
     * @param subject     subject of the identity.
     * @param lastLoginAt last sign-in, or {@code null}.
     * @return the link.
     */
    private static FederatedIdentity identity(final UUID owner, final IdentityProvider provider,
                                              final String subject, final Instant lastLoginAt) {
        return new FederatedIdentity(UUID.randomUUID(), owner, provider, subject, EMAIL,
                Instant.now().truncatedTo(ChronoUnit.MILLIS), lastLoginAt);
    }
}
