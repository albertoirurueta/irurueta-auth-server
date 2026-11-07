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
package com.irurueta.authserver.authorization.api.web.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.WebAttributes;

/** Unit tests of {@link OttAuthenticationFailureHandler}. */
class OttAuthenticationFailureHandlerTest {

    /** Handler under test. */
    private final OttAuthenticationFailureHandler handler = new OttAuthenticationFailureHandler();

    /** A wrong code goes back to the page where it is typed, keeping the failure in the session. */
    @Test
    void onAuthenticationFailure_whenACodeFailed_redirectsToTheCodePage() throws Exception {
        final var request = new MockHttpServletRequest();
        request.setParameter("token", "123456");
        final var response = new MockHttpServletResponse();
        final var failure = new BadCredentialsException("no");

        handler.onAuthenticationFailure(request, response, failure);

        assertEquals("/login/ott?error", response.getRedirectedUrl());
        assertSame(failure, request.getSession().getAttribute(WebAttributes.AUTHENTICATION_EXCEPTION));
    }

    /** A link that is not valid goes to the sign-in page. */
    @Test
    void onAuthenticationFailure_whenALinkFailed_redirectsToTheSignInPage() throws Exception {
        final var request = new MockHttpServletRequest();
        request.setParameter("token", "7b7ea0e1-1b0f-4f55-8a54-2a1f3f0a1b2c");
        final var response = new MockHttpServletResponse();

        handler.onAuthenticationFailure(request, response, new BadCredentialsException("no"));

        assertEquals("/login?error", response.getRedirectedUrl());
    }
}
