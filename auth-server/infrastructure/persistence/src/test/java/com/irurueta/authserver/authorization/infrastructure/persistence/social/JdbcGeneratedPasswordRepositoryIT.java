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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import com.irurueta.authserver.authorization.infrastructure.persistence.password.JdbcUserAccountRepository;
import com.irurueta.authserver.authorization.infrastructure.persistence.password.UserAccountRowMapper;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Integration tests of {@link JdbcGeneratedPasswordRepository} against PostgreSQL, including that setting a password
 * through {@link JdbcUserAccountRepository} clears the mark. No Spring context is needed.
 */
class JdbcGeneratedPasswordRepositoryIT {

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Repository under test. */
    private static JdbcGeneratedPasswordRepository repository;

    /** Repository of the accounts, whose password writes must clear the mark. */
    private static JdbcUserAccountRepository accounts;

    /** Identifier of the account used by the tests. */
    private UUID userId;

    /**
     * Connects to the migrated database and builds the repositories.
     */
    @BeforeAll
    static void connect() {
        jdbcClient = JdbcClient.create(MigratedPostgres.dataSource());
        repository = new JdbcGeneratedPasswordRepository(jdbcClient);
        accounts = new JdbcUserAccountRepository(jdbcClient, new UserAccountRowMapper());
    }

    /**
     * Removes the data of the previous test and creates the account.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM users").update();
        userId = UUID.randomUUID();
        accounts.save(new UserAccount(userId, "user-" + userId, "{noop}x", true, List.of()));
    }

    /**
     * Verifies that a new account does not hold a generated password.
     */
    @Test
    void isGenerated_whenAccountWasRegistered_returnsFalse() {
        assertFalse(repository.isGenerated(userId));
    }

    /**
     * Verifies that marking the password makes it generated.
     */
    @Test
    void markGenerated_whenCalled_makesPasswordGenerated() {
        repository.markGenerated(userId);

        assertTrue(repository.isGenerated(userId));
    }

    /**
     * Verifies that changing the password clears the mark.
     */
    @Test
    void isGenerated_whenPasswordIsUpdated_returnsFalse() {
        repository.markGenerated(userId);

        accounts.updatePassword(userId, "{noop}new");

        assertFalse(repository.isGenerated(userId));
    }

    /**
     * Verifies that saving the account with a password clears the mark.
     */
    @Test
    void isGenerated_whenAccountIsSavedAgain_returnsFalse() {
        repository.markGenerated(userId);

        accounts.save(new UserAccount(userId, "user-" + userId, "{noop}other", true, List.of()));

        assertFalse(repository.isGenerated(userId));
    }

    /**
     * Verifies that an unknown account has no generated password.
     */
    @Test
    void isGenerated_whenAccountIsUnknown_returnsFalse() {
        assertFalse(repository.isGenerated(UUID.randomUUID()));
    }
}
