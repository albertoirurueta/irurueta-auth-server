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

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Unit tests of {@link UrlCapturingRedirectStrategy}.
 */
class UrlCapturingRedirectStrategyTest {

    /**
     * Verifies that the URL is left in a request attribute and nothing is redirected.
     */
    @Test
    void sendRedirect_whenCalled_storesUrlWithoutRedirecting() {
        final var request = new MockHttpServletRequest();
        final var response = new MockHttpServletResponse();

        new UrlCapturingRedirectStrategy().sendRedirect(request, response, "http://x/y");

        assertEquals("http://x/y", request.getAttribute(UrlCapturingRedirectStrategy.URL_ATTRIBUTE));
        assertNull(response.getRedirectedUrl());
        assertEquals(HttpStatus.OK.value(), response.getStatus());
    }
}
