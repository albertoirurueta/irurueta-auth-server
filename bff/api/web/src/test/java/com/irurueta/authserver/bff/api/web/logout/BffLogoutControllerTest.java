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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.web.server.ResponseStatusException;

/**
 * Unit tests of {@link BffLogoutController}.
 */
@ExtendWith(MockitoExtension.class)
class BffLogoutControllerTest {

    /** URL the handler wants to redirect to. */
    private static final String LOGOUT_URL = "http://localhost:9000/connect/logout?id_token_hint=x";

    /** Handler composing the logout URL. */
    @Mock
    private OidcClientInitiatedLogoutSuccessHandler logoutSuccessHandler;

    /** The current request. */
    @Mock
    private HttpServletRequest request;

    /** The current response. */
    @Mock
    private HttpServletResponse response;

    /** Session of the request. */
    @Mock
    private HttpSession session;

    /** Controller under test. */
    @InjectMocks
    private BffLogoutController controller;

    /** Clears the user signed in by a test. */
    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    /**
     * Verifies that the URL composed by the handler is returned and the session is invalidated afterwards.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void logout_whenUserIsSignedIn_returnsLogoutUrlAndInvalidatesSession() throws Exception {
        final var authentication = new TestingAuthenticationToken("demo", null);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        doAnswer(invocation -> null).when(logoutSuccessHandler).onLogoutSuccess(request, response, authentication);
        when(request.getAttribute(UrlCapturingRedirectStrategy.URL_ATTRIBUTE)).thenReturn(LOGOUT_URL);
        when(request.getSession(false)).thenReturn(session);

        final var result = controller.logout();

        assertEquals(HttpStatus.OK, result.getStatusCode());
        assertEquals(LOGOUT_URL, result.getBody().logoutUrl());
        verify(session).invalidate();
        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    /**
     * Verifies that nobody signed in is rejected as unauthenticated.
     */
    @Test
    void logout_whenNobodyIsSignedIn_throwsAuthenticationCredentialsNotFoundException() {
        assertThrows(AuthenticationCredentialsNotFoundException.class, controller::logout);
    }

    /**
     * Verifies that a failure of the handler answers 500 and keeps the session.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void logout_whenHandlerFails_throwsInternalServerError() throws Exception {
        final var authentication = new TestingAuthenticationToken("demo", null);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        doThrow(new ServletException("boom")).when(logoutSuccessHandler)
                .onLogoutSuccess(any(), any(), any());

        final var error = assertThrows(ResponseStatusException.class, controller::logout);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, error.getStatusCode());
    }

    /**
     * Verifies that an I/O failure of the handler is also answered 500.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void logout_whenHandlerFailsWithIoError_throwsInternalServerError() throws Exception {
        final var authentication = new TestingAuthenticationToken("demo", null);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        doThrow(new IOException("boom")).when(logoutSuccessHandler).onLogoutSuccess(any(), any(), any());

        assertThrows(ResponseStatusException.class, controller::logout);
    }
}
