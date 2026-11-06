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

package com.irurueta.authserver.resourceserver.api.web.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.io.IOException;
import java.time.Duration;
import jakarta.servlet.ServletException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

/** Unit tests for {@link StepUpAccessDeniedHandler}. */
@ExtendWith(MockitoExtension.class)
class StepUpAccessDeniedHandlerTest {

    /** Handler of the ordinary denials. */
    @Mock
    private AccessDeniedHandler delegate;

    /** Step-up policy. */
    @Spy
    private StepUpProperties properties = new StepUpProperties(true, "urn:irurueta:acr:mfa", Duration.ofMinutes(5));

    /** Subject under test. */
    @InjectMocks
    private StepUpAccessDeniedHandler handler;

    /** A step-up requirement is answered 401 with the RFC 9470 challenge. */
    @Test
    void handle_whenStepUpIsRequired_answersUnauthorizedWithChallenge() throws IOException, ServletException {
        final var response = new MockHttpServletResponse();
        final var denied = new AuthorizationDeniedException("denied", new StepUpRequiredDecision());

        handler.handle(new MockHttpServletRequest(), response, denied);

        assertEquals(HttpStatus.UNAUTHORIZED.value(), response.getStatus());
        assertEquals("Bearer error=\"insufficient_user_authentication\", acr_values=\"urn:irurueta:acr:mfa\", "
                + "max_age=\"300\"", response.getHeader(HttpHeaders.WWW_AUTHENTICATE));
        verifyNoInteractions(delegate);
    }

    /** An ordinary authorization denial goes to the RFC 6750 handler. */
    @Test
    void handle_whenDenialIsOrdinary_delegates() throws IOException, ServletException {
        final var response = new MockHttpServletResponse();
        final var request = new MockHttpServletRequest();
        final var denied = new AuthorizationDeniedException("denied", new AuthorizationDecision(false));

        handler.handle(request, response, denied);

        verify(delegate).handle(request, response, denied);
    }

    /** A denial that is not an authorization denial goes to the RFC 6750 handler. */
    @Test
    void handle_whenExceptionIsPlainAccessDenied_delegates() throws IOException, ServletException {
        final var response = new MockHttpServletResponse();
        final var request = new MockHttpServletRequest();
        final var denied = new AccessDeniedException("denied");

        handler.handle(request, response, denied);

        verify(delegate).handle(request, response, denied);
    }
}
