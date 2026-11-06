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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;

/**
 * Unit tests of {@link CsrfCookieFilter}.
 */
class CsrfCookieFilterTest {

    /** Filter under test. */
    private final CsrfCookieFilter filter = new CsrfCookieFilter();

    /**
     * Verifies that the token is read, which makes the repository write its cookie, and the chain continues.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilterInternal_whenTokenIsPresent_readsItAndContinues() throws Exception {
        final var request = new MockHttpServletRequest();
        final var chain = new MockFilterChain();
        final var token = mock(CsrfToken.class);
        request.setAttribute(CsrfToken.class.getName(), token);

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        verify(token).getToken();
        assertNotNull(chain.getRequest());
    }

    /**
     * Verifies that a request without a token goes through untouched.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilterInternal_whenNoTokenIsPresent_continues() throws Exception {
        final var chain = new MockFilterChain();

        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), chain);

        assertNotNull(chain.getRequest());
    }
}
