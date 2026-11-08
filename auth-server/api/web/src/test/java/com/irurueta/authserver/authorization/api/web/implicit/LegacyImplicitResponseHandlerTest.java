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
package com.irurueta.authserver.authorization.api.web.implicit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

/**
 * Unit tests of {@link LegacyImplicitResponseHandler}.
 */
@ExtendWith(MockitoExtension.class)
class LegacyImplicitResponseHandlerTest {

    /** Status of a redirect. */
    private static final int FOUND = 302;

    /** Registered redirect URI. */
    private static final String REDIRECT_URI = "http://localhost:9000/legacy-implicit/";

    /** Lifetime of the token in seconds. */
    private static final long LIFETIME = 300;

    /** Answers the results that are not the flow's. */
    @Mock
    private AuthenticationSuccessHandler delegate;

    /** Handler under test. */
    @InjectMocks
    private LegacyImplicitResponseHandler handler;

    /**
     * Verifies that a granted request redirects with the token, its type, lifetime, scope and state in the fragment,
     * encoded, and with the headers that keep it private.
     *
     * @throws Exception never.
     */
    @Test
    void onAuthenticationSuccess_whenTheTokenIsGranted_redirectsWithTheFragment() throws Exception {
        final var now = Instant.now();
        final var accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "a.b-c", now,
                now.plusSeconds(LIFETIME), Set.of("documents.read"));
        final var result = new LegacyImplicitAccessTokenToken(accessToken, Set.of("documents.read"), REDIRECT_URI,
                "s t&=");
        final var response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, result);

        assertEquals(FOUND, response.getStatus());
        assertEquals(REDIRECT_URI + "#access_token=a.b-c&token_type=Bearer&expires_in=300&scope=documents.read"
                + "&state=s%20t%26%3D", response.getRedirectedUrl());
        assertEquals("no-store", response.getHeader("Cache-Control"));
        assertEquals("no-referrer", response.getHeader("Referrer-Policy"));
        verifyNoInteractions(delegate);
    }

    /**
     * Verifies that a granted request without state has no state in the fragment.
     *
     * @throws Exception never.
     */
    @Test
    void onAuthenticationSuccess_whenThereIsNoState_omitsIt() throws Exception {
        final var now = Instant.now();
        final var accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "t", now,
                now.plusSeconds(LIFETIME), Set.of("documents.read"));
        final var response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response,
                new LegacyImplicitAccessTokenToken(accessToken, Set.of("documents.read"), REDIRECT_URI, null));

        assertFalse(response.getRedirectedUrl().contains("state"));
    }

    /**
     * Verifies that a refusal redirects with the error and the state in the fragment.
     *
     * @throws Exception never.
     */
    @Test
    void onAuthenticationSuccess_whenTheRequestIsRefused_redirectsWithTheError() throws Exception {
        final var response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response,
                new LegacyImplicitErrorToken("invalid_scope", "bad scope", REDIRECT_URI, "abc"));

        assertEquals(FOUND, response.getStatus());
        assertEquals(REDIRECT_URI + "#error=invalid_scope&error_description=bad%20scope&state=abc",
                response.getRedirectedUrl());
        assertEquals("no-store", response.getHeader("Cache-Control"));
        assertEquals("no-referrer", response.getHeader("Referrer-Policy"));
    }

    /**
     * Verifies that a refusal without description or state has only the error.
     *
     * @throws Exception never.
     */
    @Test
    void onAuthenticationSuccess_whenTheRefusalHasNoDescriptionOrState_sendsOnlyTheError() throws Exception {
        final var response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response,
                new LegacyImplicitErrorToken("invalid_request", null, REDIRECT_URI, null));

        assertEquals(REDIRECT_URI + "#error=invalid_request", response.getRedirectedUrl());
    }

    /**
     * Verifies that any other result goes to the delegate and gets none of the headers.
     *
     * @throws Exception never.
     */
    @Test
    void onAuthenticationSuccess_whenTheResultIsAnotherOne_delegates() throws Exception {
        final var request = new MockHttpServletRequest();
        final var response = new MockHttpServletResponse();
        final var other = new TestingAuthenticationToken("alice", "secret");

        handler.onAuthenticationSuccess(request, response, other);

        verify(delegate).onAuthenticationSuccess(request, response, other);
        assertNull(response.getRedirectedUrl());
        assertTrue(response.getHeaderNames().isEmpty());
    }
}
