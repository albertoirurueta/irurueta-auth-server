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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.RequestCache;

/**
 * Unit tests of {@link ReauthenticationEntryPoint}.
 */
@ExtendWith(MockitoExtension.class)
class ReauthenticationEntryPointTest {

    /** Cache that keeps the request to resume. */
    @Mock
    private RequestCache requestCache;

    /** Repository of the session's security context. */
    @Mock
    private SecurityContextRepository securityContextRepository;

    /** Entry point under test. */
    private ReauthenticationEntryPoint entryPoint;

    /**
     * Builds the entry point.
     */
    @BeforeEach
    void setUp() {
        entryPoint = new ReauthenticationEntryPoint(requestCache, securityContextRepository);
    }

    /**
     * Leaves the thread's security context clean.
     */
    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    /**
     * Verifies that the authentication is discarded, the request saved and the user sent to the login page.
     *
     * @throws Exception never.
     */
    @Test
    void commence_whenCalled_clearsAuthenticationSavesRequestAndRedirectsToLogin() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("alice", "x"));
        final var request = new MockHttpServletRequest();
        final var response = new MockHttpServletResponse();

        entryPoint.commence(request, response, new ReauthenticationRequiredException());

        final var captor = ArgumentCaptor.<SecurityContext>captor();
        verify(securityContextRepository).saveContext(captor.capture(), any(), any());
        assertNull(captor.getValue().getAuthentication());
        assertNull(SecurityContextHolder.getContext().getAuthentication());
        verify(requestCache).saveRequest(request, response);
        assertEquals(ReauthenticationEntryPoint.LOGIN_PATH, response.getRedirectedUrl());
    }
}
