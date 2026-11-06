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

package com.irurueta.authserver.bff.api.web.login;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.web.server.ResponseStatusException;

/**
 * Unit tests of {@link BffLoginController}.
 */
@ExtendWith(MockitoExtension.class)
class BffLoginControllerTest {

    /** Port the browser used. */
    private static final int PORT = 8443;

    /** Default HTTP port. */
    private static final int HTTP_PORT = 80;

    /** Validator of the {@code returnTo} values. */
    @Mock
    private ReturnToValidator returnToValidator;

    /** The current request. */
    @Mock
    private HttpServletRequest request;

    /** Session of the request. */
    @Mock
    private HttpSession session;

    /** Controller under test. */
    @InjectMocks
    private BffLoginController controller;

    /**
     * Verifies that an allowed path is saved as the request to resume and the browser is sent to the authorization
     * request.
     */
    @Test
    void login_whenReturnToIsAllowed_savesRequestAndRedirects() {
        when(returnToValidator.isAllowed("/orders?x=1#top")).thenReturn(true);
        when(request.getSession()).thenReturn(session);
        when(request.getScheme()).thenReturn("https");
        when(request.getServerName()).thenReturn("app.example");
        when(request.getServerPort()).thenReturn(PORT);

        final var response = controller.login("/orders?x=1#top");

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals(BffLoginController.AUTHORIZATION_PATH, response.getHeaders().getLocation().toString());
        final var captor = ArgumentCaptor.<Object>captor();
        verify(session).setAttribute(eq(BffLoginController.SAVED_REQUEST_ATTRIBUTE),
                captor.capture());
        final var saved = (DefaultSavedRequest) captor.getValue();
        assertEquals("https://app.example:8443/orders?x=1", saved.getRedirectUrl());
    }

    /**
     * Verifies that a path without query string is saved as is.
     */
    @Test
    void login_whenReturnToHasNoQuery_savesThePath() {
        when(returnToValidator.isAllowed("/orders/1")).thenReturn(true);
        when(request.getSession()).thenReturn(session);
        when(request.getScheme()).thenReturn("http");
        when(request.getServerName()).thenReturn("localhost");
        when(request.getServerPort()).thenReturn(HTTP_PORT);

        controller.login("/orders/1");

        final var captor = ArgumentCaptor.<Object>captor();
        verify(session).setAttribute(eq(BffLoginController.SAVED_REQUEST_ATTRIBUTE),
                captor.capture());
        assertEquals("http://localhost/orders/1", ((DefaultSavedRequest) captor.getValue()).getRedirectUrl());
    }

    /**
     * Verifies that a missing {@code returnTo} returns to the root of the application.
     */
    @Test
    void login_whenReturnToIsMissing_returnsToRoot() {
        when(returnToValidator.isAllowed(BffLoginController.DEFAULT_RETURN_TO)).thenReturn(true);
        when(request.getSession()).thenReturn(session);
        when(request.getScheme()).thenReturn("http");
        when(request.getServerName()).thenReturn("localhost");
        when(request.getServerPort()).thenReturn(HTTP_PORT);

        final var response = controller.login(null);

        assertTrue(response.getStatusCode().is3xxRedirection());
        verify(returnToValidator).isAllowed("/");
    }

    /**
     * Verifies that a rejected {@code returnTo} answers 400 and saves nothing.
     */
    @Test
    void login_whenReturnToIsRejected_throwsBadRequest() {
        when(returnToValidator.isAllowed("//evil.example")).thenReturn(false);

        final var error = assertThrows(ResponseStatusException.class, () -> controller.login("//evil.example"));

        assertSame(HttpStatus.BAD_REQUEST, error.getStatusCode());
        verifyNoInteractions(session);
    }
}
