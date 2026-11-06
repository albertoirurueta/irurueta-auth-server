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

package com.irurueta.authserver.authorization.api.web.login;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.web.WebAttributes;

/**
 * Unit tests of {@link LoginController}.
 */
@ExtendWith(MockitoExtension.class)
class LoginControllerTest {

    /** Order of the fragment that is rendered first. */
    private static final int FIRST_ORDER = 10;

    /** Order of the fragment that is rendered second. */
    private static final int SECOND_ORDER = 20;

    /** Maps authentication exceptions to message keys. */
    @Mock
    private LoginErrorMessages errorMessages;

    /** Renders the page. */
    @Mock
    private PageRenderer pageRenderer;

    /** Fragment that is rendered first. */
    @Mock
    private LoginMethodFragment first;

    /** Fragment that is rendered second. */
    @Mock
    private LoginMethodFragment second;

    /** The current request. */
    private MockHttpServletRequest request;

    /**
     * Creates the request of each test.
     */
    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
    }

    /**
     * Verifies that the model holds an empty list when no authentication method contributes a fragment, and that
     * the rendered page is answered.
     */
    @Test
    void loginPage_whenThereAreNoFragments_putsAnEmptyList() {
        final var page = ResponseEntity.ok("<html></html>");
        when(pageRenderer.render(eq(LoginController.VIEW_NAME), anyMap())).thenReturn(page);

        final var response = controller(List.of()).loginPage(null, null);

        final var model = renderedModel();
        assertSame(page, response);
        assertEquals(LoginController.LOGIN_PATH, model.get(LoginController.LOGIN_PATH_ATTRIBUTE));
        assertTrue(((List<?>) model.get(LoginController.FRAGMENTS_ATTRIBUTE)).isEmpty());
    }

    /**
     * Verifies that the fragments are sorted by their order.
     */
    @Test
    void loginPage_whenThereAreTwoFragments_putsThemSortedByOrder() {
        when(first.order()).thenReturn(FIRST_ORDER);
        when(second.order()).thenReturn(SECOND_ORDER);

        controller(List.of(second, first)).loginPage(null, null);

        assertEquals(List.of(first, second), renderedModel().get(LoginController.FRAGMENTS_ATTRIBUTE));
    }

    /**
     * Verifies that a failed attempt puts the message key of the exception kept in the session in the model.
     */
    @Test
    void loginPage_whenPreviousAttemptFailed_putsTheMessageKeyOfTheException() {
        final var exception = new LockedException("locked");
        request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, exception);
        when(errorMessages.keyOf(exception)).thenReturn(LoginErrorMessages.LOCKED);

        controller(List.of()).loginPage("", null);

        final var model = renderedModel();
        assertEquals(LoginErrorMessages.LOCKED, model.get(LoginController.ERROR_MESSAGE_ATTRIBUTE));
        assertFalse((Boolean) model.get(LoginController.LOGGED_OUT_ATTRIBUTE));
    }

    /**
     * Verifies that a failed attempt without a session still shows an error.
     */
    @Test
    void loginPage_whenErrorHasNoSession_putsTheKeyOfNoException() {
        when(errorMessages.keyOf(null)).thenReturn(LoginErrorMessages.GENERIC);

        controller(List.of()).loginPage("", null);

        assertEquals(LoginErrorMessages.GENERIC, renderedModel().get(LoginController.ERROR_MESSAGE_ATTRIBUTE));
    }

    /**
     * Verifies that a session attribute that is not an authentication exception is ignored.
     */
    @Test
    void loginPage_whenSessionHoldsSomethingElse_putsTheKeyOfNoException() {
        request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, "not an exception");
        when(errorMessages.keyOf(null)).thenReturn(LoginErrorMessages.GENERIC);

        controller(List.of()).loginPage("", null);

        assertEquals(LoginErrorMessages.GENERIC, renderedModel().get(LoginController.ERROR_MESSAGE_ATTRIBUTE));
    }

    /**
     * Verifies that a stale exception in the session is ignored when the page is not an error page.
     */
    @Test
    void loginPage_whenThereIsNoErrorParameter_ignoresTheStoredException() {
        request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, new BadCredentialsException("x"));

        controller(List.of()).loginPage(null, null);

        assertNull(renderedModel().get(LoginController.ERROR_MESSAGE_ATTRIBUTE));
        verifyNoInteractions(errorMessages);
    }

    /**
     * Verifies that the logout parameter is reflected in the model.
     */
    @Test
    void loginPage_whenUserHasSignedOut_flagsIt() {
        controller(List.of()).loginPage(null, "");

        assertTrue((Boolean) renderedModel().get(LoginController.LOGGED_OUT_ATTRIBUTE));
    }

    /**
     * Creates the controller under test.
     *
     * @param fragments the fragments of the login methods.
     * @return the controller.
     */
    private LoginController controller(final List<LoginMethodFragment> fragments) {
        return new LoginController(fragments, errorMessages, pageRenderer, request);
    }

    /**
     * Gets the model the login template was rendered with.
     *
     * @return the model.
     */
    private Map<String, ?> renderedModel() {
        final var captor = ArgumentCaptor.<Map<String, ?>>captor();
        verify(pageRenderer).render(eq(LoginController.VIEW_NAME), captor.capture());
        return captor.getValue();
    }
}
