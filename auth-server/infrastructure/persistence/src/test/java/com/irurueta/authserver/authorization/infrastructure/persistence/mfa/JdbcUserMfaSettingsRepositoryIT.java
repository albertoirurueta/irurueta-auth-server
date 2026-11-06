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

package com.irurueta.authserver.authorization.infrastructure.persistence.mfa;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;

/**
 * Integration tests of {@link JdbcUserMfaSettingsRepository} against a migrated PostgreSQL.
 */
class JdbcUserMfaSettingsRepositoryIT {

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Repository under test. */
    private static JdbcUserMfaSettingsRepository repository;

    /** Identifier of the user. */
    private UUID userId;

    /**
     * Connects to the migrated database and builds the repository.
     */
    @BeforeAll
    static void connect() {
        jdbcClient = JdbcClient.create(MigratedPostgres.dataSource());
        repository = new JdbcUserMfaSettingsRepository(jdbcClient);
    }

    /**
     * Removes the data of the previous test and inserts the user.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM users").update();
        userId = UUID.randomUUID();
        jdbcClient.sql("INSERT INTO users (id, username) VALUES (?, ?)").params(userId, "user-" + userId).update();
    }

    /**
     * Verifies that enforcement is off by default and can be switched on and off.
     */
    @Test
    void setRequired_whenToggled_isReadBack() {
        assertFalse(repository.isRequired(userId));

        repository.setRequired(userId, true);
        assertTrue(repository.isRequired(userId));

        repository.setRequired(userId, false);
        assertFalse(repository.isRequired(userId));
    }

    /**
     * Verifies that an unknown user does not require a second factor.
     */
    @Test
    void isRequired_whenUserDoesNotExist_returnsFalse() {
        assertFalse(repository.isRequired(UUID.randomUUID()));
    }
}
