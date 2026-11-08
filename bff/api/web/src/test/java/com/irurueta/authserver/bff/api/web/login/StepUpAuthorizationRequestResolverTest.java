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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

/**
 * Unit tests of {@link StepUpAuthorizationRequestResolver}.
 */
@ExtendWith(MockitoExtension.class)
class StepUpAuthorizationRequestResolverTest {

    /** Identifier of the client registration. */
    private static final String REGISTRATION_ID = "bff";

    /** Authentication context class asked for. */
    private static final String ACR_VALUES = "urn:irurueta:acr:mfa";

    /** Maximum age, in seconds, asked for. */
    private static final long MAX_AGE = 300L;

    /** A parameter the delegate added, which must be kept. */
    private static final String NONCE = "nonce-value";

    /** Builds the authorization request. */
    @Mock
    private OAuth2AuthorizationRequestResolver delegate;

    /** Resolver under test. */
    @InjectMocks
    private StepUpAuthorizationRequestResolver resolver;

    /** The current request. */
    private MockHttpServletRequest request;

    /** Authorization request of the delegate. */
    private OAuth2AuthorizationRequest authorizationRequest;

    /**
     * Builds the request and the authorization request of the delegate.
     */
    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        authorizationRequest = OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("http://localhost:9000/oauth2/authorize")
                .clientId(REGISTRATION_ID)
                .redirectUri("http://localhost:8080/login/oauth2/code/bff")
                .state("state")
                .additionalParameters(Map.of("nonce", NONCE))
                .build();
    }

    /**
     * Verifies that the step-up values of the session are added to the authorization request, which keeps what the
     * delegate set, and are removed from the session.
     */
    @Test
    void resolve_whenSessionHoldsStepUpValues_addsThemOnce() {
        final var session = sessionWith(new StepUpLoginParameters(ACR_VALUES, MAX_AGE));
        when(delegate.resolve(request)).thenReturn(authorizationRequest);

        final var resolved = resolver.resolve(request);

        assertEquals(ACR_VALUES, resolved.getAdditionalParameters()
                .get(StepUpAuthorizationRequestResolver.ACR_VALUES_PARAMETER));
        assertEquals(String.valueOf(MAX_AGE), resolved.getAdditionalParameters()
                .get(StepUpAuthorizationRequestResolver.MAX_AGE_PARAMETER));
        assertEquals(NONCE, resolved.getAdditionalParameters().get("nonce"));
        assertTrue(resolved.getAuthorizationRequestUri().contains("max_age=" + MAX_AGE));
        assertNull(session.getAttribute(StepUpAuthorizationRequestResolver.STEP_UP_ATTRIBUTE));
    }

    /**
     * Verifies that only the values given are added.
     */
    @Test
    void resolve_whenOnlyMaxAgeIsKept_addsOnlyMaxAge() {
        sessionWith(new StepUpLoginParameters(null, MAX_AGE));
        when(delegate.resolve(request, REGISTRATION_ID)).thenReturn(authorizationRequest);

        final var parameters = resolver.resolve(request, REGISTRATION_ID).getAdditionalParameters();

        assertFalse(parameters.containsKey(StepUpAuthorizationRequestResolver.ACR_VALUES_PARAMETER));
        assertEquals(String.valueOf(MAX_AGE), parameters.get(StepUpAuthorizationRequestResolver.MAX_AGE_PARAMETER));
    }

    /**
     * Verifies that {@code acrValues} alone is added without a maximum age.
     */
    @Test
    void resolve_whenOnlyAcrValuesAreKept_addsOnlyAcrValues() {
        sessionWith(new StepUpLoginParameters(ACR_VALUES, null));
        when(delegate.resolve(request)).thenReturn(authorizationRequest);

        final var parameters = resolver.resolve(request).getAdditionalParameters();

        assertEquals(ACR_VALUES, parameters.get(StepUpAuthorizationRequestResolver.ACR_VALUES_PARAMETER));
        assertFalse(parameters.containsKey(StepUpAuthorizationRequestResolver.MAX_AGE_PARAMETER));
    }

    /**
     * Verifies that the authorization request of the delegate is returned unchanged without a session.
     */
    @Test
    void resolve_whenThereIsNoSession_returnsTheDelegatesRequest() {
        when(delegate.resolve(request)).thenReturn(authorizationRequest);

        assertSame(authorizationRequest, resolver.resolve(request));
    }

    /**
     * Verifies that the authorization request of the delegate is returned unchanged when the session holds no
     * step-up values.
     */
    @Test
    void resolve_whenSessionHoldsNoStepUpValues_returnsTheDelegatesRequest() {
        request.setSession(new MockHttpSession());
        when(delegate.resolve(request, REGISTRATION_ID)).thenReturn(authorizationRequest);

        assertSame(authorizationRequest, resolver.resolve(request, REGISTRATION_ID));
    }

    /**
     * Verifies that a request that is not an authorization request stays one, and the step-up values are kept for
     * the next authorization request.
     */
    @Test
    void resolve_whenDelegateResolvesNothing_returnsNullAndKeepsTheValues() {
        final var stepUp = new StepUpLoginParameters(ACR_VALUES, MAX_AGE);
        final var session = sessionWith(stepUp);

        assertNull(resolver.resolve(request));
        assertSame(stepUp, session.getAttribute(StepUpAuthorizationRequestResolver.STEP_UP_ATTRIBUTE));
    }

    /**
     * Gives the request a session holding step-up values.
     *
     * @param stepUp the step-up values.
     * @return the session.
     */
    private MockHttpSession sessionWith(final StepUpLoginParameters stepUp) {
        final var session = new MockHttpSession();
        session.setAttribute(StepUpAuthorizationRequestResolver.STEP_UP_ATTRIBUTE, stepUp);
        request.setSession(session);
        return session;
    }
}
