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

package com.irurueta.authserver.authorization.clients;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

class JdbcAuthorizationServerConfigurationTest {

    private final JdbcAuthorizationServerConfiguration configuration = new JdbcAuthorizationServerConfiguration();

    private final JdbcTemplate jdbcTemplate = mock(JdbcTemplate.class);

    private final RegisteredClientRepository repository = mock(RegisteredClientRepository.class);

    @Test
    void registeredClientRepository_isCreated() {
        assertThat(configuration.registeredClientRepository(jdbcTemplate)).isNotNull();
    }

    @Test
    void authorizationService_isCreated() {
        when(repository.findById("x")).thenReturn(null);

        assertThat(configuration.authorizationService(jdbcTemplate, repository)).isNotNull();
    }

    @Test
    void authorizationConsentService_isCreated() {
        assertThat(configuration.authorizationConsentService(jdbcTemplate, repository)).isNotNull();
    }
}
