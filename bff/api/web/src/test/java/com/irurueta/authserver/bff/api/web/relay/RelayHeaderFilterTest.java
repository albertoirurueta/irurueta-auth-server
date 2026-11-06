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
package com.irurueta.authserver.bff.api.web.relay;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * Unit tests of {@link RelayHeaderFilter}.
 */
class RelayHeaderFilterTest {

    /** Filter under test. */
    private final RelayHeaderFilter filter = new RelayHeaderFilter();

    /**
     * Verifies that the allowed headers are copied, whatever their case, with every value.
     */
    @Test
    void copyRequestHeaders_whenHeaderIsAllowed_copiesIt() {
        final var request = new MockHttpServletRequest();
        request.addHeader("ACCEPT", "application/json");
        request.addHeader("Accept", "text/plain");
        request.addHeader("Content-Type", "application/json");
        request.addHeader("If-None-Match", "\"v1\"");
        final var target = new HttpHeaders();

        filter.copyRequestHeaders(request, target);

        assertEquals(List.of("application/json", "text/plain"), target.get("Accept"));
        assertEquals("application/json", target.getFirst("Content-Type"));
        assertEquals("\"v1\"", target.getFirst("If-None-Match"));
    }

    /**
     * Verifies that credentials, CSRF headers and anything outside the allow-list never cross the relay.
     */
    @Test
    void copyRequestHeaders_whenHeaderIsNotAllowed_dropsIt() {
        final var request = new MockHttpServletRequest();
        request.addHeader("Cookie", "__Host-SESSION=abc");
        request.addHeader("Authorization", "Bearer browser-token");
        request.addHeader("X-CSRF-TOKEN", "csrf");
        request.addHeader("X-XSRF-TOKEN", "xsrf");
        request.addHeader("X-Custom", "value");
        final var target = new HttpHeaders();

        filter.copyRequestHeaders(request, target);

        assertTrue(target.isEmpty());
    }

    /**
     * Verifies that cookies, authentication challenges and hop-by-hop headers are not returned to the browser, while
     * the other headers are.
     */
    @Test
    void copyResponseHeaders_whenHeaderIsBlocked_dropsIt() {
        final var source = new HttpHeaders();
        source.add("Set-Cookie", "a=b");
        source.add("set-cookie2", "c=d");
        source.add("WWW-Authenticate", "Bearer");
        source.add("Transfer-Encoding", "chunked");
        source.add("Connection", "close");
        source.add("Content-Type", "application/json");
        source.add("X-Total", "1");
        source.add("X-Total", "2");
        final var response = new MockHttpServletResponse();

        filter.copyResponseHeaders(source, response);

        assertNull(response.getHeader("Set-Cookie"));
        assertNull(response.getHeader("Set-Cookie2"));
        assertNull(response.getHeader("WWW-Authenticate"));
        assertNull(response.getHeader("Transfer-Encoding"));
        assertNull(response.getHeader("Connection"));
        assertEquals("application/json", response.getContentType());
        assertEquals(List.of("1", "2"), response.getHeaders("X-Total"));
        assertFalse(response.getHeaderNames().contains("Set-Cookie"));
    }

    /**
     * Verifies that a security or caching header the BFF writes itself is not copied from the resource server, so the
     * browser gets the BFF's value only once, whatever the case of the upstream name.
     *
     * @param name the name of the header, as the resource server sent it.
     */
    @ParameterizedTest
    @MethodSource("securityHeaders")
    void copyResponseHeaders_whenHeaderIsWrittenByTheBff_dropsIt(final String name) {
        final var source = new HttpHeaders();
        source.add(name, "upstream-value");
        final var response = new MockHttpServletResponse();

        filter.copyResponseHeaders(source, response);

        assertTrue(response.getHeaderNames().isEmpty(), name);
    }

    /**
     * Provides the security and caching headers that the BFF's own header writer sets, in mixed case.
     *
     * @return the header names.
     */
    private static Stream<String> securityHeaders() {
        return Stream.of("Cache-Control", "Pragma", "Expires", "X-Content-Type-Options", "X-Frame-Options",
                "X-XSS-Protection", "Content-Security-Policy", "Strict-Transport-Security", "REFERRER-POLICY");
    }
}
