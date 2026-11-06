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

package com.irurueta.authserver.bff.api.web.security;

import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;

/**
 * Unit tests of the OAuth2 client beans of {@link SecurityConfig}; the filter chain itself is covered by the
 * integration tests.
 */
class SecurityConfigTest {

    /** Configuration under test. */
    private final SecurityConfig config = new SecurityConfig();

    /**
     * Verifies that the authorized clients are kept in the HTTP session.
     */
    @Test
    void authorizedClientRepository_whenCreated_keepsClientsInTheHttpSession() {
        assertInstanceOf(HttpSessionOAuth2AuthorizedClientRepository.class, config.authorizedClientRepository());
    }

    /**
     * Verifies that the manager is built over the registrations and the session repository.
     */
    @Test
    void authorizedClientManager_whenCreated_isBuilt() {
        assertNotNull(config.authorizedClientManager(mock(ClientRegistrationRepository.class),
                config.authorizedClientRepository()));
    }

    /**
     * Verifies that the content security policy only allows same-origin scripts and forbids framing.
     */
    @Test
    void contentSecurityPolicy_whenRead_isSameOriginAndForbidsFraming() {
        assertTrue(SecurityConfig.CONTENT_SECURITY_POLICY.contains("default-src 'self'"));
        assertTrue(SecurityConfig.CONTENT_SECURITY_POLICY.contains("frame-ancestors 'none'"));
    }
}
