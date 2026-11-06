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

import com.irurueta.authserver.authorization.infrastructure.persistence.tokens.ReuseDetectingAuthorizationService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * Registers the JDBC implementations of the Spring Authorization Server persistence services.
 */
@Configuration(proxyBeanMethods = false)
public class JdbcAuthorizationServerConfiguration {

    // tag::jdbc-services[]
    /**
     * Creates the repository of registered clients.
     *
     * @param jdbcTemplate JDBC template of the application datasource.
     * @return the registered client repository.
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository(final JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    /**
     * Creates the service that stores OAuth 2 authorizations, decorated to detect the reuse of rotated refresh
     * tokens.
     *
     * @param jdbcTemplate             JDBC template of the application datasource.
     * @param registeredClientRepository repository used to resolve the client of each authorization.
     * @param jsonMapperFactory        creates the mapper that serializes the stored attributes and claims.
     * @return the authorization service.
     */
    @Bean
    public OAuth2AuthorizationService authorizationService(
            final JdbcTemplate jdbcTemplate, final RegisteredClientRepository registeredClientRepository,
            final AuthorizationJsonMapperFactory jsonMapperFactory) {
        final var jsonMapper = jsonMapperFactory.create();
        final var service = new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
        service.setAuthorizationRowMapper(
                new JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationRowMapper(
                        registeredClientRepository, jsonMapper));
        service.setAuthorizationParametersMapper(
                new JdbcOAuth2AuthorizationService.JsonMapperOAuth2AuthorizationParametersMapper(jsonMapper));
        return new ReuseDetectingAuthorizationService(service, JdbcClient.create(jdbcTemplate));
    }

    /**
     * Creates the service that stores the consents granted by users.
     *
     * @param jdbcTemplate             JDBC template of the application datasource.
     * @param registeredClientRepository repository used to resolve the client of each consent.
     * @return the authorization consent service.
     */
    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(
            final JdbcTemplate jdbcTemplate, final RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }
    // end::jdbc-services[]
}
