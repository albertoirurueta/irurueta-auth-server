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
package com.irurueta.authserver.authorization.api.web.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import com.irurueta.authserver.authorization.domain.ott.OttPolicy;
import java.time.Duration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

/** Unit tests of {@link OttGenerateRequestResolver}. */
class OttGenerateRequestResolverTest {

    /** Lifetime of a code. */
    private static final Duration CODE_TTL = Duration.ofMinutes(10);

    /** Lifetime of a link. */
    private static final Duration LINK_TTL = Duration.ofMinutes(15);

    /** Length of a code. */
    private static final int CODE_LENGTH = 6;

    /** Attempts tolerated. */
    private static final int MAX_ATTEMPTS = 5;

    /** Resolver under test. */
    private final OttGenerateRequestResolver resolver = new OttGenerateRequestResolver(
            new OttPolicy(CODE_LENGTH, CODE_TTL, LINK_TTL, MAX_ATTEMPTS));

    /** Clears the security context. */
    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    /** A sign-in code request names the identifier of the form and lives as long as a code. */
    @Test
    void resolve_whenASignInCodeIsRequested_usesTheFormIdentifierAndTheCodeLifetime() {
        final var request = request("alice");

        final var resolved = resolver.resolve(request);

        assertEquals("alice", resolved.getUsername());
        assertEquals(CODE_TTL, resolved.getExpiresIn());
    }

    /** A sign-in link request lives as long as a link. */
    @Test
    void resolve_whenASignInLinkIsRequested_usesTheLinkLifetime() {
        final var request = request("alice");
        request.setParameter(OttGenerationParameters.KIND_PARAMETER, "link");

        final var resolved = resolver.resolve(request);

        assertEquals("alice", resolved.getUsername());
        assertEquals(LINK_TTL, resolved.getExpiresIn());
    }

    /** The identifier is cleaned of control characters. */
    @Test
    void resolve_whenTheIdentifierHasControlCharacters_removesThem() {
        assertEquals("alice", resolver.resolve(request(" \u001fal\u0000ice ")).getUsername());
    }

    /** A request without an identifier is not resolved. */
    @Test
    void resolve_whenNoIdentifierIsNamed_returnsNull() {
        assertNull(resolver.resolve(request(null)));
        assertNull(resolver.resolve(request("  \u001f ")));
    }

    /** A second-factor code names the signed-in user, never the form. */
    @Test
    void resolve_whenASecondFactorCodeIsRequested_namesTheSignedInUser() {
        signIn("alice");
        final var request = request("mallory");
        request.setParameter(OttGenerationParameters.PURPOSE_PARAMETER, "second-factor");

        assertEquals("alice", resolver.resolve(request).getUsername());
    }

    /** A second-factor link is stored with the marker, so it only works in the session of its user. */
    @Test
    void resolve_whenASecondFactorLinkIsRequested_marksTheStoredUsername() {
        signIn("alice");
        final var request = request(null);
        request.setParameter(OttGenerationParameters.PURPOSE_PARAMETER, "second-factor");
        request.setParameter(OttGenerationParameters.KIND_PARAMETER, "link");

        final var resolved = resolver.resolve(request);

        assertEquals(LinkTokenUsername.forLink("alice", true), resolved.getUsername());
        assertEquals(LINK_TTL, resolved.getExpiresIn());
    }

    /**
     * Signs a user in the security context.
     *
     * @param username the user.
     */
    private static void signIn(final String username) {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(username, "x", AuthorityUtils.NO_AUTHORITIES));
    }

    /**
     * Builds a token request.
     *
     * @param username the identifier field, or {@code null}.
     * @return the request.
     */
    private static MockHttpServletRequest request(final String username) {
        final var request = new MockHttpServletRequest("POST", "/ott/generate");
        if (username != null) {
            request.setParameter(OttGenerationParameters.USERNAME_PARAMETER, username);
        }
        return request;
    }
}
