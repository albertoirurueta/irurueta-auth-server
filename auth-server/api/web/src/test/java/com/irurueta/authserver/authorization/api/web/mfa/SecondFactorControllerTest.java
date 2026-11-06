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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.api.web.pages.PageRenderer;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
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
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;

/**
 * Unit tests of {@link SecondFactorController}.
 */
@ExtendWith(MockitoExtension.class)
class SecondFactorControllerTest {

    /** Order of the fragment that is rendered first. */
    private static final int FIRST_ORDER = 10;

    /** Order of the fragment that is rendered second. */
    private static final int SECOND_ORDER = 20;

    /** Renders the page. */
    @Mock
    private PageRenderer pageRenderer;

    /** Fragment that is rendered first. */
    @Mock
    private SecondFactorFragment first;

    /** Fragment that is rendered second. */
    @Mock
    private SecondFactorFragment second;

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
     * Clears the security context.
     */
    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    /**
     * Verifies that the model attributes each fragment contributes for the signed-in user reach the page.
     */
    @Test
    void secondFactorPage_whenFragmentsContributeAttributes_addsThemToTheModel() {
        final var user = UsernamePasswordAuthenticationToken.authenticated("alice", null, List.of());
        SecurityContextHolder.getContext().setAuthentication(user);
        when(first.modelAttributes(user)).thenReturn(Map.of("totpEnrolment", true));

        controller(List.of(first)).secondFactorPage(null);

        assertEquals(Boolean.TRUE, renderedModel().get("totpEnrolment"));
    }

    /**
     * Verifies that the fragments are sorted by order and the rendered page is answered, with no error.
     */
    @Test
    void secondFactorPage_whenThereAreFragments_putsThemSortedByOrder() {
        final var page = ResponseEntity.ok("<html></html>");
        when(first.order()).thenReturn(FIRST_ORDER);
        when(second.order()).thenReturn(SECOND_ORDER);
        when(pageRenderer.render(eq(SecondFactorController.VIEW_NAME), anyMap())).thenReturn(page);

        final var response = controller(List.of(second, first)).secondFactorPage(null);

        final var model = renderedModel();
        assertSame(page, response);
        assertEquals(List.of(first, second), model.get(SecondFactorController.FRAGMENTS_ATTRIBUTE));
        assertFalse(model.containsKey(SecondFactorController.ERROR_MESSAGE_ATTRIBUTE));
    }

    /**
     * Verifies that a failed attempt shows the generic message, also when the session holds no failure.
     */
    @Test
    void secondFactorPage_whenAttemptFailedWithoutSession_putsTheGenericMessage() {
        controller(List.of()).secondFactorPage("");

        assertEquals(SecondFactorController.GENERIC_ERROR,
                renderedModel().get(SecondFactorController.ERROR_MESSAGE_ATTRIBUTE));
    }

    /**
     * Verifies that a wrong code shows the generic message.
     */
    @Test
    void secondFactorPage_whenAttemptFailedWithBadCredentials_putsTheGenericMessage() {
        request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, new BadCredentialsException("x"));

        controller(List.of()).secondFactorPage("");

        assertEquals(SecondFactorController.GENERIC_ERROR,
                renderedModel().get(SecondFactorController.ERROR_MESSAGE_ATTRIBUTE));
    }

    /**
     * Verifies that a lockout shows the locked message.
     */
    @Test
    void secondFactorPage_whenAttemptFailedBecauseOfLockout_putsTheLockedMessage() {
        request.getSession().setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, new LockedException("locked"));

        controller(List.of()).secondFactorPage("");

        assertEquals(SecondFactorController.LOCKED_ERROR,
                renderedModel().get(SecondFactorController.ERROR_MESSAGE_ATTRIBUTE));
    }

    /**
     * Builds the controller.
     *
     * @param fragments the fragments of the second factors.
     * @return the controller.
     */
    private SecondFactorController controller(final List<SecondFactorFragment> fragments) {
        return new SecondFactorController(fragments, pageRenderer, request);
    }

    /**
     * Gets the model handed to the renderer.
     *
     * @return the model.
     */
    @SuppressWarnings("unchecked")
    private Map<String, Object> renderedModel() {
        final var captor = ArgumentCaptor.<Map<String, Object>>captor();
        verify(pageRenderer).render(eq(SecondFactorController.VIEW_NAME), captor.capture());
        return captor.getValue();
    }
}
