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

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter;

/**
 * Unit tests of {@link SessionStrategyPostProcessor}.
 */
class SessionStrategyPostProcessorTest {

    /**
     * Verifies that the session authentication strategy of the chain is handed to the WebAuthn filter.
     */
    @Test
    void postProcess_whenTheChainHasASessionStrategy_setsItOnTheFilter() {
        final var http = mock(HttpSecurity.class);
        final var strategy = mock(SessionAuthenticationStrategy.class);
        final var filter = mock(WebAuthnAuthenticationFilter.class);
        when(http.getSharedObject(SessionAuthenticationStrategy.class)).thenReturn(strategy);

        final var result = new SessionStrategyPostProcessor(http).postProcess(filter);

        assertSame(filter, result);
        verify(filter).setSessionAuthenticationStrategy(strategy);
    }

    /**
     * Verifies that the filter keeps its own strategy when the chain has none.
     */
    @Test
    void postProcess_whenTheChainHasNoSessionStrategy_leavesTheFilterAlone() {
        final var http = mock(HttpSecurity.class);
        final var filter = mock(WebAuthnAuthenticationFilter.class);

        final var result = new SessionStrategyPostProcessor(http).postProcess(filter);

        assertSame(filter, result);
        verify(filter, never()).setSessionAuthenticationStrategy(any());
    }
}
