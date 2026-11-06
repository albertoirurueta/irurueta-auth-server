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

package com.irurueta.authserver.authorization.api.web.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * Unit tests of {@link SecondFactorErrorResponseHandler}.
 */
@ExtendWith(MockitoExtension.class)
class SecondFactorErrorResponseHandlerTest {

    /** Redirect URI of the client. */
    private static final String REDIRECT_URI = "https://client.example/cb";

    /** Entry point of the second-factor page. */
    @Mock
    private AuthenticationEntryPoint secondFactorEntryPoint;

    /** Entry point that forces a new sign-in. */
    @Mock
    private AuthenticationEntryPoint reauthenticationEntryPoint;

    /** Handler under test; built by hand because both entry points have the same type. */
    private SecondFactorErrorResponseHandler handler;

    /**
     * Builds the handler.
     */
    @BeforeEach
    void setUp() {
        handler = new SecondFactorErrorResponseHandler(secondFactorEntryPoint, reauthenticationEntryPoint);
    }

    /**
     * Verifies that a missing second factor is delegated to the entry point.
     *
     * @throws Exception never.
     */
    @Test
    void onAuthenticationFailure_whenSecondFactorIsRequired_delegatesToEntryPoint() throws Exception {
        final var request = new MockHttpServletRequest();
        final var response = new MockHttpServletResponse();
        final var exception = new SecondFactorRequiredException();

        handler.onAuthenticationFailure(request, response, exception);

        verify(secondFactorEntryPoint).commence(request, response, exception);
    }

    /**
     * Verifies that a request for a more recent authentication is delegated to the re-authentication entry point.
     *
     * @throws Exception never.
     */
    @Test
    void onAuthenticationFailure_whenReauthenticationIsRequired_delegatesToReauthenticationEntryPoint()
            throws Exception {
        final var request = new MockHttpServletRequest();
        final var response = new MockHttpServletResponse();
        final var exception = new ReauthenticationRequiredException();

        handler.onAuthenticationFailure(request, response, exception);

        verify(reauthenticationEntryPoint).commence(request, response, exception);
        verifyNoInteractions(secondFactorEntryPoint);
    }

    /**
     * Verifies that an error of a request with a redirect URI is sent to the client with its state.
     *
     * @throws Exception never.
     */
    @Test
    void onAuthenticationFailure_whenRequestHasRedirectUri_redirectsToClientWithError() throws Exception {
        final var response = new MockHttpServletResponse();
        final var error = new OAuth2Error(OAuth2ErrorCodes.INVALID_SCOPE, "bad scope", "https://docs/err");

        handler.onAuthenticationFailure(new MockHttpServletRequest(), response,
                new OAuth2AuthorizationCodeRequestAuthenticationException(error, token("xyz")));

        verifyNoInteractions(secondFactorEntryPoint);
        assertEquals(REDIRECT_URI + "?error=invalid_scope&error_description=bad%20scope"
                + "&error_uri=https%3A%2F%2Fdocs%2Ferr&state=xyz", response.getRedirectedUrl());
    }

    /**
     * Verifies that an error without description, URI or state only carries its code.
     *
     * @throws Exception never.
     */
    @Test
    void onAuthenticationFailure_whenErrorHasOnlyCode_redirectsWithCodeOnly() throws Exception {
        final var response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(new MockHttpServletRequest(), response,
                new OAuth2AuthorizationCodeRequestAuthenticationException(
                        new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED), token(null)));

        assertEquals(REDIRECT_URI + "?error=access_denied", response.getRedirectedUrl());
    }

    /**
     * Verifies that an error whose request has no redirect URI answers 400.
     *
     * @throws Exception never.
     */
    @Test
    void onAuthenticationFailure_whenRequestHasNoRedirectUri_answersBadRequest() throws Exception {
        final var response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(new MockHttpServletRequest(), response,
                new OAuth2AuthorizationCodeRequestAuthenticationException(
                        new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST), null));

        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
    }

    /**
     * Verifies that an error that is not an OAuth 2.0 one answers 400.
     *
     * @throws Exception never.
     */
    @Test
    void onAuthenticationFailure_whenExceptionIsNotOAuth2_answersBadRequest() throws Exception {
        final var response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(new MockHttpServletRequest(), response, new BadCredentialsException("bad"));

        assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
    }

    /**
     * Builds the request token of a failed authorization request.
     *
     * @param state the state of the request, may be {@code null}.
     * @return the token.
     */
    private static OAuth2AuthorizationCodeRequestAuthenticationToken token(final String state) {
        return new OAuth2AuthorizationCodeRequestAuthenticationToken("https://as.example/oauth2/authorize", "client",
                new TestingAuthenticationToken("alice", null), REDIRECT_URI, state, Set.of("openid"), Map.of());
    }
}
