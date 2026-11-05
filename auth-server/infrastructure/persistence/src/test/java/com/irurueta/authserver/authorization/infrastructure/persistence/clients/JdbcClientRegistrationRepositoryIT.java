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

package com.irurueta.authserver.authorization.infrastructure.persistence.clients;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import com.irurueta.authserver.authorization.infrastructure.persistence.MigratedPostgres;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;

/**
 * Integration tests of {@link JdbcClientRegistrationRepository} over the real
 * {@link JdbcRegisteredClientRepository} and PostgreSQL. No Spring context is needed.
 */
class JdbcClientRegistrationRepositoryIT {

    /** Client id used by the tests. */
    private static final String CLIENT_ID = "bff";

    /** Lifetime of access tokens, in minutes. */
    private static final long ACCESS_MINUTES = 10;

    /** Lifetime of refresh tokens, in hours. */
    private static final long REFRESH_HOURS = 8;

    /** JDBC client connected to the database. */
    private static JdbcClient jdbcClient;

    /** Repository under test. */
    private static JdbcClientRegistrationRepository repository;

    /**
     * Connects to the migrated database and builds the repository.
     */
    @BeforeAll
    static void connect() {
        final var dataSource = MigratedPostgres.dataSource();
        jdbcClient = JdbcClient.create(dataSource);
        repository = new JdbcClientRegistrationRepository(
                new JdbcRegisteredClientRepository(new JdbcTemplate(dataSource)), jdbcClient);
    }

    /**
     * Removes the clients of the previous test.
     */
    @BeforeEach
    void cleanUp() {
        jdbcClient.sql("DELETE FROM oauth2_registered_client").update();
    }

    /**
     * Verifies that a saved client is read back as the same registration, with its audiences and token settings.
     */
    @Test
    void findByClientId_whenClientWasSaved_returnsTheSameRegistration() {
        final var registration = confidential(CLIENT_ID);

        repository.save(registration, encoded());

        assertEquals(registration, repository.findByClientId(CLIENT_ID).orElseThrow());
    }

    /**
     * Verifies that saving again replaces the settings and keeps the stored secret when none is given.
     */
    @Test
    void save_whenClientExistsAndSecretIsNull_keepsTheStoredSecret() {
        repository.save(confidential(CLIENT_ID), encoded());
        final var before = jdbcClient.sql("SELECT client_secret FROM oauth2_registered_client WHERE client_id = ?")
                .param(CLIENT_ID).query(String.class).single();
        final var updated = new ClientRegistration(CLIENT_ID, "Renamed", true, List.of("client_secret_basic"),
                List.of("authorization_code"), List.of("http://localhost:8080/login/oauth2/code/bff"),
                List.of("openid"), true, List.of("other"), Duration.ofMinutes(5), Duration.ofHours(1),
                ClientRegistration.FORMAT_REFERENCE, true);

        repository.save(updated, null);

        assertEquals(updated, repository.findByClientId(CLIENT_ID).orElseThrow());
        assertEquals(before, jdbcClient.sql("SELECT client_secret FROM oauth2_registered_client WHERE client_id = ?")
                .param(CLIENT_ID).query(String.class).single());
        assertEquals(1, repository.findAll().size());
    }

    /**
     * Verifies that every client is listed.
     */
    @Test
    void findAll_whenSeveralClientsExist_listsThemAll() {
        repository.save(confidential("a-client"), encoded());
        repository.save(confidential("b-client"), encoded());

        assertEquals(List.of("a-client", "b-client"),
                repository.findAll().stream().map(ClientRegistration::clientId).toList());
    }

    /**
     * Verifies that a client is deleted and that its secret can be replaced.
     */
    @Test
    void deleteByClientId_whenClientExists_removesIt() {
        repository.save(confidential(CLIENT_ID), encoded());
        final var replacement = encoded();

        repository.updateSecret(CLIENT_ID, replacement);

        assertEquals(replacement, jdbcClient.sql("SELECT client_secret FROM oauth2_registered_client")
                .query(String.class).single());
        repository.deleteByClientId(CLIENT_ID);
        assertTrue(repository.findByClientId(CLIENT_ID).isEmpty());
    }

    /**
     * Builds a runtime-generated placeholder for an encoded value.
     *
     * @return the placeholder.
     */
    private static String encoded() {
        return "{noop}" + UUID.randomUUID();
    }

    /**
     * Builds a confidential registration.
     *
     * @param clientId client id.
     * @return the registration.
     */
    private static ClientRegistration confidential(final String clientId) {
        return new ClientRegistration(clientId, "Backend for Frontend", true, List.of("client_secret_basic"),
                List.of("authorization_code", "refresh_token"), List.of("http://localhost:8080/login/oauth2/code/bff"),
                List.of("openid", "profile"), true, List.of("resource-server"), Duration.ofMinutes(ACCESS_MINUTES),
                Duration.ofHours(REFRESH_HOURS), ClientRegistration.FORMAT_SELF_CONTAINED, false);
    }
}
