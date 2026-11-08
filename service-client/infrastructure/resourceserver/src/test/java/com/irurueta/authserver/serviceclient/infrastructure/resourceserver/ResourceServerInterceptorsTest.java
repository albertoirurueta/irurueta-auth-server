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
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.IOException;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

/**
 * Unit tests of {@link ResourceServerInterceptors}.
 */
@ExtendWith(MockitoExtension.class)
class ResourceServerInterceptorsTest {

    /** Registration id. */
    private static final String REGISTRATION_ID = "service-client";

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

    /** Creates the DPoP proofs, when there are any. */
    @Mock
    private ObjectProvider<DPoPProofs> dpopProofs;

    /** The proofs. */
    @Mock
    private DPoPProofs proofs;

    /** Principal the token is cached under. */
    @Mock
    private Authentication principal;

    /** Next element of the chain. */
    @Mock
    private ClientHttpRequestExecution execution;

    /** Answer of the chain. */
    @Mock
    private ClientHttpResponse response;

    /**
     * Verifies that without DPoP the interceptors send a bearer token for the given registration and principal.
     *
     * @throws IOException if an interceptor fails.
     */
    @Test
    void create_whenDPoPIsOff_sendsABearerTokenOfTheRegistrationAndPrincipal() throws IOException {
        final var asked = ArgumentCaptor.<OAuth2AuthorizeRequest>captor();
        when(dpopProofs.getIfAvailable()).thenReturn(null);
        when(manager.authorize(asked.capture())).thenReturn(client());
        final var request = new MockClientHttpRequest(HttpMethod.GET, URI_CALLED);
        when(execution.execute(request, new byte[0])).thenReturn(response);
        when(response.getHeaders()).thenReturn(new HttpHeaders());
        when(response.getStatusCode()).thenReturn(HttpStatus.OK);

        final var interceptors = new ResourceServerInterceptors(manager, dpopProofs)
                .create(REGISTRATION_ID, principal);
        final var oauth = interceptors.getFirst();
        final var guard = interceptors.getLast();
        oauth.intercept(request, new byte[0], (req, body) -> guard.intercept(req, body, execution));

        assertEquals(2, interceptors.size());
        assertInstanceOf(OAuth2ClientHttpRequestInterceptor.class, oauth);
        assertEquals("Bearer the-token", request.getHeaders().getFirst("Authorization"));
        assertEquals(REGISTRATION_ID, asked.getValue().getClientRegistrationId());
        assertEquals(principal, asked.getValue().getPrincipal());
    }

    /**
     * Verifies that a call is refused when the manager returned no authorized client.
     *
     * @throws IOException if the execution fails.
     */
    @Test
    void create_whenNoTokenIsAvailable_refusesTheCall() throws IOException {
        when(dpopProofs.getIfAvailable()).thenReturn(null);
        final var request = new MockClientHttpRequest(HttpMethod.GET, URI_CALLED);
        final var interceptors = new ResourceServerInterceptors(manager, dpopProofs)
                .create(REGISTRATION_ID, principal);
        final var guard = interceptors.getLast();
        final var body = new byte[0];

        assertThrows(ClientAuthorizationException.class, () -> guard.intercept(request, body, execution));

        verify(execution, never()).execute(any(), any());
    }

    /**
     * Verifies that with DPoP the only interceptor is the DPoP one.
     */
    @Test
    void create_whenDPoPIsOn_returnsTheDPoPInterceptorAlone() {
        when(dpopProofs.getIfAvailable()).thenReturn(proofs);

        final List<?> interceptors = new ResourceServerInterceptors(manager, dpopProofs)
                .create(REGISTRATION_ID, principal);

        assertEquals(1, interceptors.size());
        assertInstanceOf(DPoPClientHttpRequestInterceptor.class, interceptors.getFirst());
    }

    /**
     * Builds an authorized client with a bearer token.
     *
     * @return the authorized client.
     */
    private static OAuth2AuthorizedClient client() {
        final var now = Instant.now();
        return new OAuth2AuthorizedClient(REGISTRATION, "name", new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, "the-token", now, now.plusSeconds(LIFETIME_SECONDS)));
    }
}
