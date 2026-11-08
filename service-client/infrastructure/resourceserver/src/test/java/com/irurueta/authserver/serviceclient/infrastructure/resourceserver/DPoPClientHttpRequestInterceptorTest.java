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


package com.irurueta.authserver.serviceclient.infrastructure.resourceserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

/**
 * Unit tests of {@link DPoPClientHttpRequestInterceptor}.
 */
@ExtendWith(MockitoExtension.class)
class DPoPClientHttpRequestInterceptorTest {

    /** Registration id. */
    private static final String REGISTRATION_ID = "service-client";

    /** Value of the token. */
    private static final String TOKEN = "the-token";

    /** URI called. */
    private static final URI URI_CALLED = URI.create("https://rs.example.com/api/documents");

    /** Lifetime of the token, in seconds. */
    private static final long LIFETIME_SECONDS = 300L;

    /** Registration of the client. */
    private static final ClientRegistration REGISTRATION = ClientRegistration.withRegistrationId(REGISTRATION_ID)
            .clientId("client")
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .tokenUri("https://auth.example.com/oauth2/token")
            .build();

    /** Obtains the access token. */
    @Mock
    private OAuth2AuthorizedClientManager manager;

    /** Creates the proofs. */
    @Mock
    private DPoPProofs proofs;

    /** Next element of the chain. */
    @Mock
    private ClientHttpRequestExecution execution;

    /** Answer of the chain. */
    @Mock
    private ClientHttpResponse response;

    /** Principal the token is cached under. */
    @Mock
    private Authentication principal;

    /**
     * Verifies that a DPoP-bound token is sent with the DPoP scheme and a proof that binds the call and the token.
     *
     * @throws IOException if the interceptor fails.
     */
    @Test
    void intercept_whenTokenIsDPoPBound_sendsDPoPSchemeAndProof() throws IOException {
        final var request = new MockClientHttpRequest(HttpMethod.GET, URI_CALLED);
        when(manager.authorize(any(OAuth2AuthorizeRequest.class)))
                .thenReturn(client(OAuth2AccessToken.TokenType.DPOP));
        when(proofs.proof("GET", URI_CALLED, TOKEN)).thenReturn("the-proof");
        when(execution.execute(request, new byte[0])).thenReturn(response);

        final var result = new DPoPClientHttpRequestInterceptor(manager, proofs, REGISTRATION_ID, principal)
                .intercept(request, new byte[0], execution);

        assertEquals(response, result);
        assertEquals("DPoP " + TOKEN, request.getHeaders().getFirst("Authorization"));
        assertEquals("the-proof", request.getHeaders().getFirst(DPoPClientHttpRequestInterceptor.DPOP_HEADER));
    }

    /**
     * Verifies that a plain bearer token is sent as a bearer token without a proof.
     *
     * @throws IOException if the interceptor fails.
     */
    @Test
    void intercept_whenTokenIsBearer_sendsBearerWithoutProof() throws IOException {
        final var request = new MockClientHttpRequest(HttpMethod.GET, URI_CALLED);
        when(manager.authorize(any(OAuth2AuthorizeRequest.class)))
                .thenReturn(client(OAuth2AccessToken.TokenType.BEARER));
        when(execution.execute(request, new byte[0])).thenReturn(response);

        new DPoPClientHttpRequestInterceptor(manager, proofs, REGISTRATION_ID, principal)
                .intercept(request, new byte[0], execution);

        assertEquals("Bearer " + TOKEN, request.getHeaders().getFirst("Authorization"));
        assertNull(request.getHeaders().getFirst(DPoPClientHttpRequestInterceptor.DPOP_HEADER));
        verifyNoInteractions(proofs);
    }

    /**
     * Verifies that the manager is asked for the registration and principal of the interceptor.
     *
     * @throws IOException if the interceptor fails.
     */
    @Test
    void intercept_whenCalled_asksTheManagerForItsRegistrationAndPrincipal() throws IOException {
        final var request = new MockClientHttpRequest(HttpMethod.GET, URI_CALLED);
        final var asked = ArgumentCaptor.<OAuth2AuthorizeRequest>captor();
        when(manager.authorize(asked.capture())).thenReturn(client(OAuth2AccessToken.TokenType.BEARER));
        when(execution.execute(request, new byte[0])).thenReturn(response);

        new DPoPClientHttpRequestInterceptor(manager, proofs, REGISTRATION_ID, principal)
                .intercept(request, new byte[0], execution);

        assertEquals(REGISTRATION_ID, asked.getValue().getClientRegistrationId());
        assertEquals(principal, asked.getValue().getPrincipal());
    }

    /**
     * Verifies that a call without a token is never sent.
     *
     * @throws IOException if the execution fails.
     */
    @Test
    void intercept_whenNoTokenIsAvailable_throwsClientAuthorizationExceptionAndSendsNothing() throws IOException {
        final var request = new MockClientHttpRequest(HttpMethod.GET, URI_CALLED);
        when(manager.authorize(any(OAuth2AuthorizeRequest.class))).thenReturn(null);
        final var interceptor = new DPoPClientHttpRequestInterceptor(manager, proofs, REGISTRATION_ID, principal);
        final var body = new byte[0];

        assertThrows(ClientAuthorizationException.class, () -> interceptor.intercept(request, body, execution));

        assertFalse(request.getHeaders().containsHeader("Authorization"));
        verify(execution, never()).execute(any(), any());
    }

    /**
     * Builds an authorized client with a token of a type.
     *
     * @param type type of the token.
     * @return the authorized client.
     */
    private static OAuth2AuthorizedClient client(final OAuth2AccessToken.TokenType type) {
        final var now = Instant.now();
        return new OAuth2AuthorizedClient(REGISTRATION, "name",
                new OAuth2AccessToken(type, TOKEN, now, now.plusSeconds(LIFETIME_SECONDS)));
    }
}
