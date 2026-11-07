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
package com.irurueta.authserver.authorization.infrastructure.persistence.x509;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.x509.CertificateBinding;
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
 * Integration tests of {@link JdbcCertificateBindingRepository} against PostgreSQL. No Spring context is needed.
 */
class JdbcCertificateBindingRepositoryIT {

    /** Fingerprint used by the tests. */
    private static final String FINGERPRINT = "f".repeat(CertificateBinding.FINGERPRINT_LENGTH);

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Repository under test. */
    private static JdbcCertificateBindingRepository repository;

    /** Identifier of the user that owns the bindings. */
    private UUID userId;

    /**
     * Connects to the migrated database and builds the repository.
     */
    @BeforeAll
    static void connect() {
        jdbcClient = JdbcClient.create(MigratedPostgres.dataSource());
        repository = new JdbcCertificateBindingRepository(jdbcClient, new CertificateBindingRowMapper());
    }

    /**
     * Removes the data of the previous test and inserts the user that owns the bindings.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM users").update();
        userId = insertUser();
    }

    /**
     * Verifies that a stored binding is found by its fingerprint, with every field round-tripped.
     */
    @Test
    void findByFingerprintSha256_whenBound_returnsIt() {
        final var binding = binding(userId, FINGERPRINT);
        repository.save(binding);

        assertEquals(binding, repository.findByFingerprintSha256(FINGERPRINT).orElseThrow());
    }

    /**
     * Verifies that an unbound fingerprint is not found.
     */
    @Test
    void findByFingerprintSha256_whenNotBound_returnsEmpty() {
        assertTrue(repository.findByFingerprintSha256(FINGERPRINT).isEmpty());
    }

    /**
     * Verifies that one certificate cannot be bound to two accounts.
     */
    @Test
    void save_whenCertificateIsBoundToAnotherAccount_throwsDuplicateKeyException() {
        repository.save(binding(userId, FINGERPRINT));
        final var other = binding(insertUser(), FINGERPRINT);

        assertThrows(DuplicateKeyException.class, () -> repository.save(other));
    }

    /**
     * Verifies that the bindings of an account are listed oldest first, and only the account's own.
     */
    @Test
    void findByUser_whenAccountsHaveBindings_listsOnlyTheAccountsOldestFirst() {
        final var now = Instant.now().truncatedTo(ChronoUnit.MILLIS);
        final var older = new CertificateBinding(UUID.randomUUID(), userId, fingerprint("1"), "CN=old",
                now.minusSeconds(10));
        final var newer = new CertificateBinding(UUID.randomUUID(), userId, fingerprint("2"), "CN=new", now);
        repository.save(newer);
        repository.save(older);
        repository.save(binding(insertUser(), fingerprint("3")));

        assertEquals(List.of(older, newer), repository.findByUser(userId));
    }

    /**
     * Verifies that a binding is deleted only by its owner.
     */
    @Test
    void delete_whenUserIsNotTheOwner_deletesOnlyForOwner() {
        final var binding = binding(userId, FINGERPRINT);
        repository.save(binding);

        assertFalse(repository.delete(binding.id(), UUID.randomUUID()));
        assertTrue(repository.delete(binding.id(), userId));
        assertTrue(repository.findByUser(userId).isEmpty());
    }

    /**
     * Verifies that the bindings disappear with their account.
     */
    @Test
    void delete_whenAccountIsDeleted_cascadesToItsBindings() {
        repository.save(binding(userId, FINGERPRINT));

        jdbcClient.sql("DELETE FROM users WHERE id = ?").param(userId).update();

        assertTrue(repository.findByFingerprintSha256(FINGERPRINT).isEmpty());
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
     * Builds a fingerprint made of one digit.
     *
     * @param digit hexadecimal digit.
     * @return the fingerprint.
     */
    private static String fingerprint(final String digit) {
        return digit.repeat(CertificateBinding.FINGERPRINT_LENGTH);
    }

    /**
     * Builds a binding.
     *
     * @param owner       account that owns the binding.
     * @param fingerprint fingerprint of the certificate.
     * @return the binding.
     */
    private static CertificateBinding binding(final UUID owner, final String fingerprint) {
        return new CertificateBinding(UUID.randomUUID(), owner, fingerprint, "CN=alice",
                Instant.now().truncatedTo(ChronoUnit.MILLIS));
    }
}
