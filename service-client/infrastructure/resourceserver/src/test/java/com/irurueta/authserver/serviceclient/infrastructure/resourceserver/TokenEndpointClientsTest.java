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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.TokenExchangeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;

/**
 * Unit tests of {@link TokenEndpointClients}. The token endpoint is a request factory that records the request and
 * answers a canned token, so the requests the clients build can be read without a network.
 */
@ExtendWith(MockitoExtension.class)
class TokenEndpointClientsTest {

    /** Token endpoint. */
    private static final URI TOKEN_URI = URI.create("https://auth.example.com/oauth2/token");

    /** Answer of the token endpoint. */
    private static final String TOKEN_RESPONSE = "{\"access_token\":\"issued\",\"token_type\":\"Bearer\","
            + "\"expires_in\":300}";

    /** Lifetime of the tokens of the tests, in seconds. */
    private static final long LIFETIME_SECONDS = 300L;

    /** Request factory that presents the client certificate. */
    @Mock
    private SslRequestFactories requestFactories;

    /** Creates the DPoP proofs, when there are any. */
    @Mock
    private ObjectProvider<DPoPProofs> dpopProofs;

    /** Request factory that records what the clients send. */
    @Mock
    private ClientHttpRequestFactory factory;

    /** Requests the clients sent. */
    private final List<MockClientHttpRequest> sent = new ArrayList<>();

    /**
     * Makes the request factory record the requests and answer a token.
     *
     * @throws IOException if the factory cannot be stubbed.
     */
    @BeforeEach
    void setUp() throws IOException {
        lenient().when(factory.createRequest(any(), any())).thenAnswer(invocation -> {
            final var request = new MockClientHttpRequest(invocation.getArgument(1), invocation.<URI>getArgument(0));
            final var response = new MockClientHttpResponse(TOKEN_RESPONSE.getBytes(StandardCharsets.UTF_8),
                    HttpStatus.OK);
            response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
            request.setResponse(response);
            sent.add(request);
            return request;
        });
    }

    /**
     * Verifies that with the default method and nothing else configured a client is built that needs no extra setup.
     */
    @Test
    void clientCredentials_whenMethodIsClientSecretBasic_buildsAClientWithoutExtraSetup() {
        when(requestFactories.create()).thenReturn(Optional.empty());
        when(dpopProofs.getIfAvailable()).thenReturn(null);

        final var clients = new TokenEndpointClients(properties(AuthMethod.CLIENT_SECRET_BASIC),
                mock(PrivateKeyJwkResolver.class), requestFactories, dpopProofs);

        assertNotNull(clients.clientCredentials());
        assertNotNull(clients.tokenExchange());
    }

    /**
     * Verifies that the assertion of {@code private_key_jwt} is sent and verifies with the configured key.
     *
     * @throws Exception if the assertion cannot be parsed or verified.
     */
    @Test
    void clientCredentials_whenMethodIsPrivateKeyJwt_sendsAnAssertionSignedWithTheConfiguredKey() throws Exception {
        final var pair = TestKeys.rsaKeyPair();
        final var resolver = new PrivateKeyJwkResolver(
                new ServiceClientKeyProperties(TestKeys.pkcs8Pem(pair), null, null));
        when(requestFactories.create()).thenReturn(Optional.of(factory));
        when(dpopProofs.getIfAvailable()).thenReturn(null);
        final var clients = new TokenEndpointClients(properties(AuthMethod.PRIVATE_KEY_JWT), resolver,
                requestFactories, dpopProofs);

        final var response = clients.clientCredentials()
                .getTokenResponse(new OAuth2ClientCredentialsGrantRequest(registration(AuthMethod.PRIVATE_KEY_JWT)));

        assertEquals("issued", response.getAccessToken().getTokenValue());
        final var request = sent.getFirst();
        assertEquals("client_credentials", parameter(request, "grant_type"));
        final var assertion = SignedJWT.parse(parameter(request, "client_assertion"));
        assertTrue(assertion.verify(new RSASSAVerifier((RSAPublicKey) pair.getPublic())));
        assertEquals(TOKEN_URI.toString(), assertion.getJWTClaimsSet().getAudience().getFirst());
        assertNull(parameter(request, "client_secret"));
    }

    /**
     * Verifies that a DPoP proof that binds the token request is sent when DPoP is on.
     *
     * @throws Exception if the proof cannot be parsed.
     */
    @Test
    void clientCredentials_whenDPoPIsOn_sendsAProofOfTheTokenRequest() throws Exception {
        final var proofs = mock(DPoPProofs.class);
        when(proofs.proof("POST", TOKEN_URI)).thenReturn("the-proof");
        when(requestFactories.create()).thenReturn(Optional.of(factory));
        when(dpopProofs.getIfAvailable()).thenReturn(proofs);
        final var clients = new TokenEndpointClients(properties(AuthMethod.TLS_CLIENT_AUTH),
                mock(PrivateKeyJwkResolver.class), requestFactories, dpopProofs);

        clients.clientCredentials()
                .getTokenResponse(new OAuth2ClientCredentialsGrantRequest(registration(AuthMethod.TLS_CLIENT_AUTH)));

        assertEquals("the-proof", sent.getFirst().getHeaders().getFirst("DPoP"));
        assertFalse(sent.getFirst().getHeaders().containsHeader("Authorization"));
    }

    /**
     * Verifies that the exchange sends the subject and the actor token.
     *
     * @throws IOException if the request cannot be read.
     */
    @Test
    void tokenExchange_whenTokensAreGiven_sendsSubjectAndActorToken() throws IOException {
        when(requestFactories.create()).thenReturn(Optional.of(factory));
        when(dpopProofs.getIfAvailable()).thenReturn(null);
        final var clients = new TokenEndpointClients(properties(AuthMethod.TLS_CLIENT_AUTH),
                mock(PrivateKeyJwkResolver.class), requestFactories, dpopProofs);
        final var exchange = new ServiceClientRegistrationMapper()
                .tokenExchange(properties(AuthMethod.TLS_CLIENT_AUTH));

        clients.tokenExchange().getTokenResponse(new TokenExchangeGrantRequest(exchange, token("user-token"),
                token("actor-token")));

        final var request = sent.getFirst();
        assertEquals("urn:ietf:params:oauth:grant-type:token-exchange", parameter(request, "grant_type"));
        assertEquals("user-token", parameter(request, "subject_token"));
        assertEquals("actor-token", parameter(request, "actor_token"));
    }

    /**
     * Builds the settings.
     *
     * @param method the authentication method.
     * @return the settings.
     */
    private static ServiceClientAuthProperties properties(final AuthMethod method) {
        return new ServiceClientAuthProperties(method, "client", "secret", TOKEN_URI, List.of("documents.read"),
                Duration.ZERO, false, null);
    }

    /**
     * Builds the registration the assertion is for.
     *
     * @param method the authentication method.
     * @return the registration.
     */
    private static ClientRegistration registration(final AuthMethod method) {
        return new ServiceClientRegistrationMapper().clientCredentials(properties(method));
    }

    /**
     * Reads the form body of a sent request.
     *
     * @param request the request.
     * @param name    name of the parameter.
     * @return its decoded value, or {@code null}.
     */
    private static String parameter(final MockClientHttpRequest request, final String name) {
        for (final var pair : request.getBodyAsString().split("&")) {
            final var parts = pair.split("=", 2);
            if (parts[0].equals(name)) {
                return URLDecoder.decode(parts[1], StandardCharsets.UTF_8);
            }
        }
        return null;
    }

    /**
     * Builds a token.
     *
     * @param value value of the token.
     * @return the token.
     */
    private static OAuth2Token token(final String value) {
        final var now = Instant.now();
        return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, value, now, now.plusSeconds(LIFETIME_SECONDS));
    }
}
