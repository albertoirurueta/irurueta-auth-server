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

package com.irurueta.authserver.authorization.infrastructure.persistence.passkeys;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.web.webauthn.management.JdbcPublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.JdbcUserCredentialRepository;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;

/**
 * Registers the JDBC implementations of the Spring Security WebAuthn stores. The WebAuthn configurer of the web
 * adapter finds them as beans, so registrations and sign-ins persist in the {@code user_entities} and
 * {@code user_credentials} tables instead of the in-memory defaults.
 */
@Configuration(proxyBeanMethods = false)
public class WebAuthnJdbcConfiguration {

    // tag::passkeys-jdbc-repositories[]
    /**
     * Creates the store of WebAuthn user entities (the user handle, the account name and its display name).
     *
     * @param jdbcTemplate JDBC template of the application datasource.
     * @return the user entity repository.
     */
    @Bean
    public PublicKeyCredentialUserEntityRepository publicKeyCredentialUserEntityRepository(
            final JdbcTemplate jdbcTemplate) {
        return new JdbcPublicKeyCredentialUserEntityRepository(jdbcTemplate);
    }

    /**
     * Creates the store of WebAuthn credentials (public key, signature counter, flags and label).
     *
     * @param jdbcTemplate JDBC template of the application datasource.
     * @return the credential repository.
     */
    @Bean
    public UserCredentialRepository userCredentialRepository(final JdbcTemplate jdbcTemplate) {
        return new JdbcUserCredentialRepository(jdbcTemplate);
    }
    // end::passkeys-jdbc-repositories[]
}
