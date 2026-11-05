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

package com.irurueta.authserver.authorization.infrastructure.persistence.password;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.DockerImageName;

/**
 * Integration tests of {@link JdbcUserAccountRepository} against a PostgreSQL container whose schema is created
 * by the Flyway migrations of this module. No Spring context is needed.
 */
@Testcontainers
class JdbcUserAccountRepositoryIT {

    /** Docker image of the database; the same major version as {@code compose.yaml}. */
    private static final String POSTGRES_IMAGE = "postgres:18";

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Encoded password used by the tests; not a real credential. */
    private static final String ENCODED_PASSWORD = "{noop}encoded";

    /** Authority used by the tests. */
    private static final String ROLE_USER = "ROLE_USER";

    /** Another authority used by the tests. */
    private static final String ROLE_ADMIN = "ROLE_ADMIN";

    /** Database container, shared by every test of the class. */
    @Container
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer(
            DockerImageName.parse(POSTGRES_IMAGE));

    /** JDBC client connected to the container. */
    private static JdbcClient jdbcClient;

    /** Repository under test. */
    private static JdbcUserAccountRepository repository;

    /**
     * Creates the schema with the Flyway migrations of this module and builds the repository.
     */
    @BeforeAll
    static void migrateAndCreateRepository() {
        Flyway.configure()
                .dataSource(POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword())
                .load()
                .migrate();
        final var dataSource = new DriverManagerDataSource(
                POSTGRES.getJdbcUrl(), POSTGRES.getUsername(), POSTGRES.getPassword());
        jdbcClient = JdbcClient.create(dataSource);
        repository = new JdbcUserAccountRepository(jdbcClient);
    }

    /**
     * Removes the users of the previous test; their passwords and authorities cascade.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM users").update();
    }

    /**
     * Verifies that an existing user is returned with its password and enabled flag.
     */
    @Test
    void findByUsername_whenUserExists_returnsAccount() {
        final var id = insertUser(USERNAME, true, ROLE_USER);

        final var account = repository.findByUsername(USERNAME).orElseThrow();

        assertEquals(id, account.id());
        assertEquals(USERNAME, account.username());
        assertEquals(ENCODED_PASSWORD, account.encodedPassword());
        assertTrue(account.enabled());
    }

    /**
     * Verifies that a disabled user is returned as disabled.
     */
    @Test
    void findByUsername_whenUserIsDisabled_returnsDisabledAccount() {
        insertUser(USERNAME, false, ROLE_USER);

        assertFalse(repository.findByUsername(USERNAME).orElseThrow().enabled());
    }

    /**
     * Verifies that an empty result is returned when no user has the username.
     */
    @Test
    void findByUsername_whenUserIsMissing_returnsEmpty() {
        assertTrue(repository.findByUsername("nobody").isEmpty());
    }

    /**
     * Verifies that every authority of the user is loaded, sorted by name.
     */
    @Test
    void findByUsername_whenUserHasAuthorities_loadsThemSorted() {
        insertUser(USERNAME, true, ROLE_USER, ROLE_ADMIN);

        final var account = repository.findByUsername(USERNAME).orElseThrow();

        assertEquals(List.of(ROLE_ADMIN, ROLE_USER), account.authorities());
    }

    /**
     * Verifies that a user without authorities has an empty list of authorities.
     */
    @Test
    void findByUsername_whenUserHasNoAuthorities_returnsEmptyAuthorities() {
        insertUser(USERNAME, true);

        assertTrue(repository.findByUsername(USERNAME).orElseThrow().authorities().isEmpty());
    }

    /**
     * Inserts a user with its password and authorities.
     *
     * @param username    name of the user.
     * @param enabled     whether the user is enabled.
     * @param authorities authorities granted to the user.
     * @return identifier of the inserted user.
     */
    private static UUID insertUser(final String username, final boolean enabled, final String... authorities) {
        final var id = UUID.randomUUID();
        jdbcClient.sql("INSERT INTO users (id, username, enabled) VALUES (?, ?, ?)")
                .params(id, username, enabled).update();
        jdbcClient.sql("INSERT INTO user_passwords (user_id, encoded_password) VALUES (?, ?)")
                .params(id, ENCODED_PASSWORD).update();
        for (final var authority : authorities) {
            jdbcClient.sql("INSERT INTO user_authorities (user_id, authority) VALUES (?, ?)")
                    .params(id, authority).update();
        }
        return id;
    }
}
