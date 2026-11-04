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

import static org.assertj.core.api.Assertions.assertThat;

import com.irurueta.authserver.testsupport.PostgresIT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;

@PostgresIT
class JdbcServicesIT {

    @Autowired
    private RegisteredClientRepository clients;

    @Autowired
    private OAuth2AuthorizationService authorizations;

    @Autowired
    private OAuth2AuthorizationConsentService consents;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void flywayCreatesSchema() {
        final var count = jdbcTemplate.queryForObject(
                "SELECT count(*) FROM information_schema.tables WHERE table_name IN "
                        + "('oauth2_registered_client','oauth2_authorization','oauth2_authorization_consent',"
                        + "'users','user_authorities','user_passwords')", Integer.class);
        assertThat(count).isEqualTo(6);
    }

    @Test
    void servicesPersistClientAuthorizationAndConsent() {
        final var client = RegisteredClient.withId("id-1").clientId("client-1")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).scope("read").build();
        clients.save(client);
        assertThat(clients.findByClientId("client-1")).isNotNull();

        final var authorization = OAuth2Authorization.withRegisteredClient(client).id("auth-1")
                .principalName("alice").authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizedScopes(java.util.Set.of("read")).build();
        authorizations.save(authorization);
        assertThat(authorizations.findById("auth-1")).isNotNull();

        consents.save(OAuth2AuthorizationConsent.withId("id-1", "alice").scope("read").build());
        assertThat(consents.findById("id-1", "alice")).isNotNull();
    }
}
