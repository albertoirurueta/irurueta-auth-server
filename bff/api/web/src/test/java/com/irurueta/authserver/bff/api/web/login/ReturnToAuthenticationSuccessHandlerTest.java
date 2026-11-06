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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.web.WebAttributes;

/**
 * Unit tests of {@link ReturnToAuthenticationSuccessHandler}.
 */
@ExtendWith(MockitoExtension.class)
class ReturnToAuthenticationSuccessHandlerTest {

    /** An allowed path with a query string. */
    private static final String RETURN_TO = "/orders?x=1";

    /** Validator of the {@code returnTo} values. */
    @Mock
    private ReturnToValidator returnToValidator;

    /** Handler under test. */
    @InjectMocks
    private ReturnToAuthenticationSuccessHandler handler;

    /**
     * Verifies that an allowed {@code returnTo} is redirected to and removed from the session, and that the error of
     * an earlier failed attempt is cleared.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void onAuthenticationSuccess_whenReturnToIsAllowed_redirectsThereAndRemovesIt() throws Exception {
        when(returnToValidator.isAllowed(RETURN_TO)).thenReturn(true);
        final var session = new MockHttpSession();
        session.setAttribute(ReturnToAuthenticationSuccessHandler.RETURN_TO_ATTRIBUTE, RETURN_TO);
        session.setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, new IllegalStateException("earlier failure"));
        final var request = new MockHttpServletRequest();
        request.setSession(session);
        final var response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, new TestingAuthenticationToken("demo", null));

        assertEquals(RETURN_TO, response.getRedirectedUrl());
        assertNull(session.getAttribute(ReturnToAuthenticationSuccessHandler.RETURN_TO_ATTRIBUTE));
        assertNull(session.getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION));
    }

    /**
     * Verifies that a {@code returnTo} the validator no longer allows is removed and replaced by the root.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void onAuthenticationSuccess_whenReturnToIsNotAllowed_redirectsToRoot() throws Exception {
        when(returnToValidator.isAllowed("//evil.example")).thenReturn(false);
        final var session = new MockHttpSession();
        session.setAttribute(ReturnToAuthenticationSuccessHandler.RETURN_TO_ATTRIBUTE, "//evil.example");
        final var request = new MockHttpServletRequest();
        request.setSession(session);
        final var response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, new TestingAuthenticationToken("demo", null));

        assertEquals(ReturnToAuthenticationSuccessHandler.DEFAULT_TARGET, response.getRedirectedUrl());
        assertNull(session.getAttribute(ReturnToAuthenticationSuccessHandler.RETURN_TO_ATTRIBUTE));
    }

    /**
     * Verifies that a session without {@code returnTo} goes to the root without asking the validator.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void onAuthenticationSuccess_whenReturnToIsAbsent_redirectsToRoot() throws Exception {
        final var request = new MockHttpServletRequest();
        request.setSession(new MockHttpSession());
        final var response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, new TestingAuthenticationToken("demo", null));

        assertEquals(ReturnToAuthenticationSuccessHandler.DEFAULT_TARGET, response.getRedirectedUrl());
        verify(returnToValidator, never()).isAllowed(null);
    }

    /**
     * Verifies that a request without a session goes to the root.
     *
     * @throws Exception if the handler fails.
     */
    @Test
    void onAuthenticationSuccess_whenThereIsNoSession_redirectsToRoot() throws Exception {
        final var request = new MockHttpServletRequest();
        final var response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, new TestingAuthenticationToken("demo", null));

        assertEquals(ReturnToAuthenticationSuccessHandler.DEFAULT_TARGET, response.getRedirectedUrl());
    }
}
