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
package com.irurueta.authserver.authorization.api.web.social;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * Unit tests of {@link PendingIdentityLinks}.
 */
class PendingIdentityLinksTest {

    /** Name of the signed-in user. */
    private static final String USERNAME = "alice";

    /** The instant the marker is recorded at. */
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    /** Identifier of the signed-in account. */
    private final UUID userId = UUID.randomUUID();

    /** The session of the browser. */
    private final MockHttpSession session = new MockHttpSession();

    /** The request of the provider's answer. */
    private final MockHttpServletRequest request = new MockHttpServletRequest();

    /**
     * Binds the request to the thread, as the request context filter does.
     */
    @BeforeEach
    void bindRequest() {
        request.setSession(session);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    /**
     * Clears what the tests bound to the thread.
     */
    @AfterEach
    void clear() {
        RequestContextHolder.resetRequestAttributes();
        SecurityContextHolder.clearContext();
    }

    /**
     * Verifies that a marker recorded by the signed-in user is consumed once for its provider, and that the
     * authentication of the session is kept for the success handler.
     */
    @Test
    void consume_whenTheMarkerIsUsable_returnsItOnceAndKeepsTheAuthentication() {
        final var current = signIn(USERNAME);
        links(NOW).begin(session, IdentityProvider.GOOGLE, userId, USERNAME);

        final var link = links(NOW).consume(IdentityProvider.GOOGLE).orElseThrow();

        assertEquals(userId, link.userId());
        assertEquals(NOW.plus(PendingIdentityLinks.LIFETIME), link.expiresAt());
        assertSame(current, links(NOW).linkedBy(request).orElseThrow());
        assertTrue(links(NOW).consume(IdentityProvider.GOOGLE).isEmpty());
    }

    /**
     * Verifies that a marker of another provider is not used, and is removed all the same.
     */
    @Test
    void consume_whenTheMarkerNamesAnotherProvider_returnsEmptyAndRemovesIt() {
        signIn(USERNAME);
        links(NOW).begin(session, IdentityProvider.GITHUB, userId, USERNAME);

        assertTrue(links(NOW).consume(IdentityProvider.GOOGLE).isEmpty());
        assertNull(session.getAttribute(PendingIdentityLinks.SESSION_ATTRIBUTE));
        assertTrue(links(NOW).linkedBy(request).isEmpty());
    }

    /**
     * Verifies that an expired marker is not used.
     */
    @Test
    void consume_whenTheMarkerExpired_returnsEmpty() {
        signIn(USERNAME);
        links(NOW).begin(session, IdentityProvider.GOOGLE, userId, USERNAME);

        final var later = NOW.plus(PendingIdentityLinks.LIFETIME).plusSeconds(1);

        assertTrue(links(later).consume(IdentityProvider.GOOGLE).isEmpty());
    }

    /**
     * Verifies that a marker is not used once the session is signed in as somebody else, or nobody.
     */
    @Test
    void consume_whenTheSessionIsNoLongerTheAccountThatAsked_returnsEmpty() {
        signIn("mallory");
        links(NOW).begin(session, IdentityProvider.GOOGLE, userId, USERNAME);

        assertTrue(links(NOW).consume(IdentityProvider.GOOGLE).isEmpty());

        SecurityContextHolder.clearContext();
        links(NOW).begin(session, IdentityProvider.GOOGLE, userId, USERNAME);

        assertTrue(links(NOW).consume(IdentityProvider.GOOGLE).isEmpty());
    }

    /**
     * Verifies that there is nothing to consume without a request, a session or a marker.
     */
    @Test
    void consume_whenThereIsNoMarker_returnsEmpty() {
        assertTrue(links(NOW).consume(IdentityProvider.GOOGLE).isEmpty());

        request.setSession(null);
        final var withoutSession = new MockHttpServletRequest();
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(withoutSession));
        assertTrue(links(NOW).consume(IdentityProvider.GOOGLE).isEmpty());

        RequestContextHolder.resetRequestAttributes();
        assertTrue(links(NOW).consume(IdentityProvider.GOOGLE).isEmpty());
    }

    /**
     * Builds the markers over a fixed clock.
     *
     * @param instant the instant of the clock.
     * @return the markers.
     */
    private static PendingIdentityLinks links(final Instant instant) {
        return new PendingIdentityLinks(Clock.fixed(instant, ZoneOffset.UTC));
    }

    /**
     * Signs a user in.
     *
     * @param username name of the user.
     * @return the authentication.
     */
    private static UsernamePasswordAuthenticationToken signIn(final String username) {
        final var authentication = UsernamePasswordAuthenticationToken.authenticated(username, null, List.of());
        SecurityContextHolder.setContext(new SecurityContextImpl(authentication));
        return authentication;
    }
}
