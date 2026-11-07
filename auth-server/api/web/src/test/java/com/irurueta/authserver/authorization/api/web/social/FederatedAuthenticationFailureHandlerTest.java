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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

/**
 * Unit tests of {@link FederatedAuthenticationFailureHandler}.
 */
@ExtendWith(MockitoExtension.class)
class FederatedAuthenticationFailureHandlerTest {

    /** The handler of every other failure. */
    @Mock
    private AuthenticationFailureHandler delegate;

    /** Handler under test. */
    @InjectMocks
    private FederatedAuthenticationFailureHandler handler;

    /**
     * Verifies that a refused link goes back to the identities page.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void onAuthenticationFailure_whenTheLinkIsRefused_redirectsToTheIdentitiesPage() throws Exception {
        final var response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(new MockHttpServletRequest(), response,
                new OAuth2AuthenticationException(new OAuth2Error(FederatedAccountResolver.LINK_REFUSED)));

        assertEquals("/account/identities?status=already-linked", response.getRedirectedUrl());
        verifyNoInteractions(delegate);
    }

    /**
     * Verifies that any other failure is left to the delegate.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void onAuthenticationFailure_whenTheSignInIsRefused_delegates() throws Exception {
        final var request = new MockHttpServletRequest();
        final var response = new MockHttpServletResponse();
        final var exception = new OAuth2AuthenticationException(new OAuth2Error(OAuth2ErrorCodes.ACCESS_DENIED));

        handler.onAuthenticationFailure(request, response, exception);

        verify(delegate).onAuthenticationFailure(request, response, exception);
    }

    /**
     * Verifies that a failure that is not an OAuth 2.0 one is left to the delegate.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void onAuthenticationFailure_whenTheFailureIsOfAnotherKind_delegates() throws Exception {
        final var request = new MockHttpServletRequest();
        final var response = new MockHttpServletResponse();
        final var exception = new BadCredentialsException("bad");

        handler.onAuthenticationFailure(request, response, exception);

        verify(delegate).onAuthenticationFailure(request, response, exception);
    }
}
