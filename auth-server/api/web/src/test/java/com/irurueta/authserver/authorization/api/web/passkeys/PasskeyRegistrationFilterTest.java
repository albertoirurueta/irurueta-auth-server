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

package com.irurueta.authserver.authorization.api.web.passkeys;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Unit tests of {@link PasskeyRegistrationFilter}.
 */
class PasskeyRegistrationFilterTest {

    /**
     * Verifies that a request the manager refuses never reaches the rest of the chain.
     */
    @Test
    @SuppressWarnings("unchecked")
    void doFilter_whenManagerRefuses_throwsAccessDeniedAndStopsTheChain() {
        final var manager = mock(AuthorizationManager.class);
        final var chain = mock(FilterChain.class);
        when(manager.authorize(any(), any(HttpServletRequest.class))).thenReturn(new AuthorizationDecision(false));
        final var filter = new PasskeyRegistrationFilter(manager);
        SecurityContextHolder.clearContext();

        assertThrows(AuthorizationDeniedException.class, () -> filter.doFilter(
                new MockHttpServletRequest("POST", "/webauthn/register/options"), new MockHttpServletResponse(),
                chain));
        verifyNoInteractions(chain);
    }

    /**
     * Verifies that a request the manager grants goes on.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    @SuppressWarnings("unchecked")
    void doFilter_whenManagerGrants_continuesTheChain() throws Exception {
        final var manager = mock(AuthorizationManager.class);
        final var chain = mock(FilterChain.class);
        when(manager.authorize(any(), any(HttpServletRequest.class))).thenReturn(new AuthorizationDecision(true));
        final var request = new MockHttpServletRequest("GET", "/login");
        final var response = new MockHttpServletResponse();

        new PasskeyRegistrationFilter(manager).doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }
}
