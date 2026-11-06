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

package com.irurueta.authserver.bff.api.web.logout;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

/**
 * Unit tests of {@link LogoutConfiguration}.
 */
class LogoutConfigurationTest {

    /**
     * Verifies that the handler built captures the URL instead of redirecting; with a principal that is not an OIDC
     * login the handler falls back to its default target, the root of the application.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void oidcLogoutSuccessHandler_whenLogoutSucceeds_capturesUrlInsteadOfRedirecting() throws Exception {
        final var handler = new LogoutConfiguration().oidcLogoutSuccessHandler(
                mock(ClientRegistrationRepository.class));
        final var request = new MockHttpServletRequest();
        final var response = new MockHttpServletResponse();

        handler.onLogoutSuccess(request, response, new TestingAuthenticationToken("demo", null));

        assertEquals("/", request.getAttribute(UrlCapturingRedirectStrategy.URL_ATTRIBUTE));
        assertNull(response.getRedirectedUrl());
    }
}
