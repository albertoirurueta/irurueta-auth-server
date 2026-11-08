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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;

/**
 * Unit tests of {@link LegacyImplicitAuthorizationRequestConverter}.
 */
class LegacyImplicitAuthorizationRequestConverterTest {

    /** Path of the authorization endpoint. */
    private static final String AUTHORIZE = "/oauth2/authorize";

    /** Client of the legacy flow. */
    private static final String CLIENT_ID = "legacy-implicit-spa";

    /** Redirect URI. */
    private static final String REDIRECT_URI = "http://localhost:9000/legacy-implicit/";

    /** Converter under test. */
    private final LegacyImplicitAuthorizationRequestConverter converter =
            new LegacyImplicitAuthorizationRequestConverter(CLIENT_ID, AUTHORIZE);

    /**
     * Clears the security context.
     */
    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    /**
     * Verifies that a request of the legacy client is read, with its scopes split and the signed-in user.
     */
    @Test
    void convert_whenTheLegacyClientAsksForAToken_returnsTheRequest() {
        final var user = new TestingAuthenticationToken("alice", "secret");
        SecurityContextHolder.getContext().setAuthentication(user);
        final var request = request(CLIENT_ID);
        request.setParameter("scope", "documents.read  profile");
        request.setParameter("redirect_uri", REDIRECT_URI);
        request.setParameter("state", "abc");

        final var token = assertInstanceOf(LegacyImplicitAuthorizationRequestToken.class, converter.convert(request));

        assertEquals(CLIENT_ID, token.getClientId());
        assertEquals(REDIRECT_URI, token.getRedirectUri());
        assertEquals(Set.of("documents.read", "profile"), token.getScopes());
        assertEquals("abc", token.getState());
        assertSame(user, token.getPrincipal());
    }

    /**
     * Verifies that a request without a signed-in user carries an anonymous one, and that optional parameters are
     * {@code null}.
     */
    @Test
    void convert_whenThereIsNoUser_carriesAnAnonymousOne() {
        final var token = assertInstanceOf(LegacyImplicitAuthorizationRequestToken.class,
                converter.convert(request(CLIENT_ID)));

        assertInstanceOf(AnonymousAuthenticationToken.class, token.getPrincipal());
        assertTrue(token.getScopes().isEmpty());
        assertNull(token.getRedirectUri());
        assertNull(token.getState());
    }

    /**
     * Verifies that a request that is not for a token, or not a GET of the endpoint, is left to the other converters.
     */
    @Test
    void convert_whenTheRequestIsNotAnImplicitOne_returnsNull() {
        final var code = request(CLIENT_ID);
        code.setParameter("response_type", "code");
        final var post = new MockHttpServletRequest("POST", AUTHORIZE);
        post.setParameter("response_type", "token");
        final var other = new MockHttpServletRequest("GET", "/oauth2/token");
        other.setParameter("response_type", "token");

        assertNull(converter.convert(code));
        assertNull(converter.convert(post));
        assertNull(converter.convert(other));
    }

    /**
     * Verifies that any other client, or none, is refused with {@code unsupported_response_type} and no redirect.
     */
    @Test
    void convert_whenTheClientIsNotTheLegacyOne_throwsUnsupportedResponseType() {
        final var other = assertThrows(OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> converter.convert(request("spa-public")));
        final var none = assertThrows(OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> converter.convert(request(null)));

        assertEquals("unsupported_response_type", other.getError().getErrorCode());
        assertNull(other.getAuthorizationCodeRequestAuthentication());
        assertEquals("unsupported_response_type", none.getError().getErrorCode());
    }

    /**
     * Verifies that a repeated parameter is refused with {@code invalid_request} and no redirect.
     */
    @Test
    void convert_whenAParameterIsRepeated_throwsInvalidRequest() {
        final var request = request(CLIENT_ID);
        request.addParameter("state", "a");
        request.addParameter("state", "b");

        final var error = assertThrows(OAuth2AuthorizationCodeRequestAuthenticationException.class,
                () -> converter.convert(request));

        assertEquals("invalid_request", error.getError().getErrorCode());
        assertNull(error.getAuthorizationCodeRequestAuthentication());
    }

    /**
     * Builds a request for a token.
     *
     * @param clientId the client, may be {@code null}.
     * @return the request.
     */
    private static MockHttpServletRequest request(final String clientId) {
        final var request = new MockHttpServletRequest("GET", AUTHORIZE);
        request.setParameter("response_type", "token");
        if (clientId != null) {
            request.setParameter("client_id", clientId);
        }
        return request;
    }
}
