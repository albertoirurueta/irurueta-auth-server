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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

/**
 * Unit tests of {@link BffLoginController}.
 */
@ExtendWith(MockitoExtension.class)
class BffLoginControllerTest {

    /** An allowed path with a query string and a fragment. */
    private static final String RETURN_TO = "/orders?x=1#top";

    /** Authentication context class of a step-up login. */
    private static final String ACR_VALUES = "urn:irurueta:acr:mfa";

    /** Maximum age, in seconds, of a step-up login. */
    private static final Long MAX_AGE = 300L;

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
     * Verifies that an allowed path is kept in the session under the attribute of the BFF and the browser is sent to
     * the authorization request.
     */
    @Test
    void login_whenReturnToIsAllowed_keepsItInTheSessionAndRedirects() {
        when(returnToValidator.isAllowed(RETURN_TO)).thenReturn(true);
        when(request.getSession()).thenReturn(session);

        final var response = controller.login(RETURN_TO, null, null);

        assertEquals(HttpStatus.FOUND, response.getStatusCode());
        assertEquals(BffLoginController.AUTHORIZATION_PATH, response.getHeaders().getLocation().toString());
        verify(session).setAttribute(ReturnToAuthenticationSuccessHandler.RETURN_TO_ATTRIBUTE, RETURN_TO);
        verify(session).removeAttribute(StepUpAuthorizationRequestResolver.STEP_UP_ATTRIBUTE);
    }

    /**
     * Verifies that the step-up values are kept in the session for the authorization request.
     */
    @Test
    void login_whenStepUpValuesAreGiven_keepsThemInTheSession() {
        when(returnToValidator.isAllowed(RETURN_TO)).thenReturn(true);
        when(request.getSession()).thenReturn(session);

        controller.login(RETURN_TO, ACR_VALUES, MAX_AGE);

        verify(session).setAttribute(StepUpAuthorizationRequestResolver.STEP_UP_ATTRIBUTE,
                new StepUpLoginParameters(ACR_VALUES, MAX_AGE));
    }

    /**
     * Verifies that a maximum age alone is kept, and a blank {@code acrValues} is not.
     */
    @Test
    void login_whenOnlyMaxAgeIsGiven_keepsItWithoutAcrValues() {
        when(returnToValidator.isAllowed(RETURN_TO)).thenReturn(true);
        when(request.getSession()).thenReturn(session);

        controller.login(RETURN_TO, " ", MAX_AGE);

        verify(session).setAttribute(StepUpAuthorizationRequestResolver.STEP_UP_ATTRIBUTE,
                new StepUpLoginParameters(null, MAX_AGE));
    }

    /**
     * Verifies that {@code acrValues} alone is kept.
     */
    @Test
    void login_whenOnlyAcrValuesAreGiven_keepsThemWithoutMaxAge() {
        when(returnToValidator.isAllowed(RETURN_TO)).thenReturn(true);
        when(request.getSession()).thenReturn(session);

        controller.login(RETURN_TO, ACR_VALUES, null);

        verify(session).setAttribute(StepUpAuthorizationRequestResolver.STEP_UP_ATTRIBUTE,
                new StepUpLoginParameters(ACR_VALUES, null));
    }

    /**
     * Verifies that a missing {@code returnTo} returns to the root of the application.
     */
    @Test
    void login_whenReturnToIsMissing_returnsToRoot() {
        when(returnToValidator.isAllowed(BffLoginController.DEFAULT_RETURN_TO)).thenReturn(true);
        when(request.getSession()).thenReturn(session);

        final var response = controller.login(null, null, null);

        assertTrue(response.getStatusCode().is3xxRedirection());
        verify(session).setAttribute(ReturnToAuthenticationSuccessHandler.RETURN_TO_ATTRIBUTE,
                BffLoginController.DEFAULT_RETURN_TO);
    }

    /**
     * Verifies that a blank {@code returnTo} returns to the root of the application.
     */
    @Test
    void login_whenReturnToIsBlank_returnsToRoot() {
        when(returnToValidator.isAllowed(BffLoginController.DEFAULT_RETURN_TO)).thenReturn(true);
        when(request.getSession()).thenReturn(session);

        controller.login("  ", null, null);

        verify(session).setAttribute(ReturnToAuthenticationSuccessHandler.RETURN_TO_ATTRIBUTE,
                BffLoginController.DEFAULT_RETURN_TO);
    }

    /**
     * Verifies that a rejected {@code returnTo} answers 400 and keeps nothing.
     */
    @Test
    void login_whenReturnToIsRejected_throwsBadRequest() {
        when(returnToValidator.isAllowed("//evil.example")).thenReturn(false);

        final var error = assertThrows(ResponseStatusException.class,
                () -> controller.login("//evil.example", ACR_VALUES, MAX_AGE));

        assertSame(HttpStatus.BAD_REQUEST, error.getStatusCode());
        verifyNoInteractions(session);
    }
}
