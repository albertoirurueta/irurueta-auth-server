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

package com.irurueta.authserver.authorization;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.irurueta.authserver.testsupport.PostgresIT;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * Checks the JDBC services of Spring Authorization Server and the Flyway schema against a PostgreSQL container.
 */
@PostgresIT
class JdbcServicesIT {

    /** Number of tables the migrations create. */
    private static final int TABLE_COUNT = 6;

    /** Name of the scope used by the tests. */
    private static final String SCOPE = "read";

    /** Name of the principal used by the tests. */
    private static final String PRINCIPAL = "alice";

    /** Repository of registered clients. */
    @Autowired
    private RegisteredClientRepository clients;

    /** Service that stores the authorizations. */
    @Autowired
    private OAuth2AuthorizationService authorizations;

    /** Service that stores the consents. */
    @Autowired
    private OAuth2AuthorizationConsentService consents;

    /** JDBC template of the application datasource. */
    @Autowired
    private JdbcTemplate jdbcTemplate;

    /**
     * Verifies that Flyway creates every table of the schema.
     */
    @Test
    void flywayMigration_whenApplicationStarts_createsSchema() {
        final var count = jdbcTemplate.queryForObject(
                "SELECT count(*) FROM information_schema.tables WHERE table_name IN "
                        + "('oauth2_registered_client','oauth2_authorization','oauth2_authorization_consent',"
                        + "'users','user_authorities','user_passwords')", Integer.class);

        assertEquals(TABLE_COUNT, count);
    }

    /**
     * Verifies that a client, an authorization and a consent can be stored and read back.
     */
    @Test
    void services_whenDataIsSaved_persistClientAuthorizationAndConsent() {
        final var client = RegisteredClient.withId("id-1").clientId("client-1")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope(SCOPE).build();
        clients.save(client);
        assertNotNull(clients.findByClientId("client-1"));

        final var authorization = OAuth2Authorization.withRegisteredClient(client).id("auth-1")
                .principalName(PRINCIPAL).authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizedScopes(Set.of(SCOPE)).build();
        authorizations.save(authorization);
        assertNotNull(authorizations.findById("auth-1"));

        consents.save(OAuth2AuthorizationConsent.withId("id-1", PRINCIPAL).scope(SCOPE).build());
        assertNotNull(consents.findById("id-1", PRINCIPAL));
    }
}
