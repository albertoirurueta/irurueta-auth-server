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

import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * Unit tests of {@link JdbcAuthorizationServerConfiguration}.
 */
@ExtendWith(MockitoExtension.class)
class JdbcAuthorizationServerConfigurationTest {

    /** Configuration under test. */
    private final JdbcAuthorizationServerConfiguration configuration = new JdbcAuthorizationServerConfiguration();

    /** JDBC template given to the factory methods. */
    @Mock
    private JdbcTemplate jdbcTemplate;

    /** Repository of registered clients given to the factory methods. */
    @Mock
    private RegisteredClientRepository repository;

    /**
     * Verifies that the registered client repository is created.
     */
    @Test
    void registeredClientRepository_whenCalled_createsRepository() {
        assertNotNull(configuration.registeredClientRepository(jdbcTemplate));
    }

    /**
     * Verifies that the authorization service is created.
     */
    @Test
    void authorizationService_whenCalled_createsService() {
        final var factory = new AuthorizationJsonMapperFactory(List.<AuthorizationJacksonModuleContributor>of());
        assertNotNull(configuration.authorizationService(jdbcTemplate, repository, factory));
    }

    /**
     * Verifies that the authorization consent service is created.
     */
    @Test
    void authorizationConsentService_whenCalled_createsService() {
        assertNotNull(configuration.authorizationConsentService(jdbcTemplate, repository));
    }
}
