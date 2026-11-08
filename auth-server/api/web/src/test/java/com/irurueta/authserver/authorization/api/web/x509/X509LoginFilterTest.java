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
package com.irurueta.authserver.authorization.api.web.x509;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Unit tests of {@link X509LoginFilter}.
 */
class X509LoginFilterTest {

    /** Filter under test, which authenticates no request. */
    private final X509LoginFilter filter = new X509LoginFilter();

    /**
     * Verifies that the chain goes on when the response was left alone.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenTheResponseIsNotCommitted_continuesTheChain() throws Exception {
        filter.setRequiresAuthenticationRequestMatcher(request -> false);
        final var chain = new MockFilterChain();

        filter.doFilter(new MockHttpServletRequest(), new MockHttpServletResponse(), chain);

        assertNotNull(chain.getRequest());
    }

    /**
     * Verifies that a sign-in request nobody answered, because it carried no usable certificate, goes back to the
     * login page and not on to a path nothing serves.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenASignInRequestCarriesNoCertificate_redirectsToTheLoginPage() throws Exception {
        filter.setRequiresAuthenticationRequestMatcher(request -> true);
        final var response = new MockHttpServletResponse();
        final var chain = new MockFilterChain();

        filter.doFilter(new MockHttpServletRequest(), response, chain);

        assertEquals("/login?error", response.getRedirectedUrl());
        assertNull(chain.getRequest());
    }

    /**
     * Verifies that the chain stops when a handler already answered, as a redirect does.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void doFilter_whenTheResponseIsCommitted_stopsTheChain() throws Exception {
        filter.setRequiresAuthenticationRequestMatcher(request -> false);
        final var response = new MockHttpServletResponse();
        response.setCommitted(true);
        final var chain = new MockFilterChain();

        filter.doFilter(new MockHttpServletRequest(), response, chain);

        assertNull(chain.getRequest());
    }
}
