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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.web.savedrequest.RequestCache;

/**
 * Unit tests of {@link SecondFactorRequiredEntryPoint}.
 */
@ExtendWith(MockitoExtension.class)
class SecondFactorRequiredEntryPointTest {

    /** Cache that keeps the request to resume. */
    @Mock
    private RequestCache requestCache;

    /** Entry point under test. */
    @InjectMocks
    private SecondFactorRequiredEntryPoint entryPoint;

    /**
     * Verifies that the request is saved and the user is redirected to the second-factor page.
     *
     * @throws Exception never.
     */
    @Test
    void commence_whenSecondFactorIsRequired_savesRequestAndRedirects() throws Exception {
        final var request = new MockHttpServletRequest("GET", "/oauth2/authorize");
        final var response = new MockHttpServletResponse();

        entryPoint.commence(request, response, new InsufficientAuthenticationException("second factor"));

        verify(requestCache).saveRequest(request, response);
        assertEquals("/login/second-factor", response.getRedirectedUrl());
    }

    /**
     * Verifies that the context path is honoured by the redirect.
     *
     * @throws Exception never.
     */
    @Test
    void commence_whenApplicationHasContextPath_redirectsInsideIt() throws Exception {
        final var request = new MockHttpServletRequest("GET", "/auth/oauth2/authorize");
        request.setContextPath("/auth");
        final var response = new MockHttpServletResponse();

        entryPoint.commence(request, response, new InsufficientAuthenticationException("second factor"));

        assertEquals("/auth/login/second-factor", response.getRedirectedUrl());
    }
}
