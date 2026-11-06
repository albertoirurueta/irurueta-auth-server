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

package com.irurueta.authserver.bff.session;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import jakarta.servlet.http.Cookie;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.session.web.http.CookieSerializer.CookieValue;

/**
 * Unit tests of {@link SessionConfiguration}.
 */
class SessionConfigurationTest {

    /** Value written in the cookie. */
    private static final String SESSION_ID = "abc123";

    /** Configuration under test. */
    private final SessionConfiguration configuration = new SessionConfiguration();

    /**
     * Verifies that the cookie is a {@code __Host-} cookie: named so, Secure, HttpOnly, SameSite=Lax, path / and with
     * no Domain attribute.
     */
    @Test
    void cookieSerializer_whenCookieIsWritten_hasHostPrefixAndHardenedAttributes() {
        final var request = new MockHttpServletRequest();
        final var response = new MockHttpServletResponse();

        configuration.cookieSerializer().writeCookieValue(new CookieValue(request, response, SESSION_ID));

        final var header = response.getHeader("Set-Cookie");
        assertTrue(header.startsWith("__Host-SESSION="), header);
        assertTrue(header.contains("; Secure"), header);
        assertTrue(header.contains("; HttpOnly"), header);
        assertTrue(header.contains("; SameSite=Lax"), header);
        assertTrue(header.contains("; Path=/"), header);
        assertFalse(header.contains("Domain"), header);
    }

    /**
     * Verifies that the serializer reads back the cookie it writes, under the same name.
     */
    @Test
    void cookieSerializer_whenCookieIsRead_returnsSessionId() {
        final var request = new MockHttpServletRequest();
        final var response = new MockHttpServletResponse();
        final var serializer = configuration.cookieSerializer();
        serializer.writeCookieValue(new CookieValue(request, response, SESSION_ID));
        final var written = response.getHeader("Set-Cookie");
        final var cookieValue = written.substring(written.indexOf('=') + 1, written.indexOf(';'));
        request.setCookies(new Cookie(SessionConfiguration.COOKIE_NAME, cookieValue));

        assertEquals(List.of(SESSION_ID), serializer.readCookieValues(request));
    }
}
