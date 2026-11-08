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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;

/**
 * Unit tests of {@link AuthorizationCodeResponseHandler}.
 */
class AuthorizationCodeResponseHandlerTest {

    /** Redirect URI. */
    private static final String REDIRECT_URI = "https://client.example/cb";

    /** Lifetime of the code in seconds. */
    private static final long LIFETIME = 60;

    /** Handler under test. */
    private final AuthorizationCodeResponseHandler handler = new AuthorizationCodeResponseHandler();

    /**
     * Verifies that the code and the encoded state are sent in the query.
     *
     * @throws Exception never.
     */
    @Test
    void onAuthenticationSuccess_whenTheCodeIsGranted_redirectsWithCodeAndState() throws Exception {
        final var result = result("the-code", "a b");
        final var response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, result);

        assertEquals(REDIRECT_URI + "?code=the-code&state=a%20b", response.getRedirectedUrl());
    }

    /**
     * Verifies that a request without state sends only the code.
     *
     * @throws Exception never.
     */
    @Test
    void onAuthenticationSuccess_whenThereIsNoState_sendsOnlyTheCode() throws Exception {
        final var response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(new MockHttpServletRequest(), response, result("the-code", null));

        assertEquals(REDIRECT_URI + "?code=the-code", response.getRedirectedUrl());
    }

    /**
     * Verifies that a result without code is refused.
     */
    @Test
    void onAuthenticationSuccess_whenThereIsNoCode_throwsIllegalArgumentException() {
        final var result = mock(OAuth2AuthorizationCodeRequestAuthenticationToken.class);
        when(result.getRedirectUri()).thenReturn(REDIRECT_URI);
        final var request = new MockHttpServletRequest();
        final var response = new MockHttpServletResponse();

        assertThrows(IllegalArgumentException.class, () -> handler.onAuthenticationSuccess(request, response, result));
    }

    /**
     * Builds a granted result.
     *
     * @param code  the code.
     * @param state the state, may be {@code null}.
     * @return the result.
     */
    private static OAuth2AuthorizationCodeRequestAuthenticationToken result(final String code, final String state) {
        final var now = Instant.now();
        final var result = mock(OAuth2AuthorizationCodeRequestAuthenticationToken.class);
        when(result.getRedirectUri()).thenReturn(REDIRECT_URI);
        when(result.getAuthorizationCode()).thenReturn(new OAuth2AuthorizationCode(code, now,
                now.plusSeconds(LIFETIME)));
        when(result.getState()).thenReturn(state);
        return result;
    }
}
