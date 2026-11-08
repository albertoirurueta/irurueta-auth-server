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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.serviceclient.infrastructure.resourceserver.v1.generated.api.DocumentsApi;
import java.net.URI;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.endpoint.OAuth2ClientCredentialsGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientClientCredentialsTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.RestClientTokenExchangeTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.TokenExchangeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;

/**
 * Unit tests of {@link OAuth2ClientConfiguration}. The clients of the token endpoint are mocks, so what is verified is
 * how the authorized client manager uses them: when it asks for a token, when it reuses one and what it sends.
 */
@ExtendWith(MockitoExtension.class)
class OAuth2ClientConfigurationTest {

    /** Lifetime of a long-lived token, in seconds. */
    private static final long LONG_LIFETIME_SECONDS = 300L;

    /** Lifetime of a token that is inside the refresh margin, in seconds. */
    private static final long SHORT_LIFETIME_SECONDS = 30L;

    /** Margin before the expiry at which tokens are renewed. */
    private static final Duration REFRESH_BEFORE = Duration.ofSeconds(60);

    /** Configuration under test. */
    private final OAuth2ClientConfiguration configuration = new OAuth2ClientConfiguration();

    /** Builds the principals; the real one. */
    @Spy
    private PrincipalMapper principalMapper;

    /** Client of the token endpoint for the client credentials grant. */
    @Mock
    private RestClientClientCredentialsTokenResponseClient clientCredentialsClient;

    /** Client of the token endpoint for the token exchange grant. */
    @Mock
    private RestClientTokenExchangeTokenResponseClient tokenExchangeClient;

    /** Builds the clients of the token endpoint. */
    @Mock
    private TokenEndpointClients tokenClients;

    /** Builds documents clients. */
    @Mock
    private DocumentsApis documentsApis;

    /** Documents client of the service client. */
    @Mock
    private DocumentsApi documentsApi;

    /**
     * Verifies that the repository holds the client credentials and the token exchange registrations.
     */
    @Test
    void serviceClientRegistrations_whenCalled_holdsBothRegistrations() {
        final var registrations = registrations();

        assertNotNull(registrations.findByRegistrationId(
                ServiceClientRegistrationMapper.CLIENT_CREDENTIALS_REGISTRATION_ID));
        assertNotNull(registrations.findByRegistrationId(
                ServiceClientRegistrationMapper.TOKEN_EXCHANGE_REGISTRATION_ID));
    }

    /**
     * Verifies that a token that is valid beyond the refresh margin is reused, so the token endpoint is asked once.
     */
    @Test
    void serviceClientAuthorizedClientManager_whenTokenIsValid_reusesIt() {
        when(tokenClients.clientCredentials()).thenReturn(clientCredentialsClient);
        when(clientCredentialsClient.getTokenResponse(any())).thenReturn(response("cc-token", LONG_LIFETIME_SECONDS));
        final var manager = manager();
        final var request = clientCredentialsRequest();

        final var first = manager.authorize(request);
        final var second = manager.authorize(request);

        assertEquals("cc-token", first.getAccessToken().getTokenValue());
        assertSame(first.getAccessToken(), second.getAccessToken());
        verify(clientCredentialsClient, times(1)).getTokenResponse(any(OAuth2ClientCredentialsGrantRequest.class));
    }

    /**
     * Verifies that a token that is inside the refresh margin is renewed instead of being reused.
     */
    @Test
    void serviceClientAuthorizedClientManager_whenTokenIsWithinTheRefreshMargin_renewsIt() {
        when(tokenClients.clientCredentials()).thenReturn(clientCredentialsClient);
        when(clientCredentialsClient.getTokenResponse(any())).thenReturn(response("cc-token", SHORT_LIFETIME_SECONDS));
        final var manager = manager();
        final var request = clientCredentialsRequest();

        manager.authorize(request);
        manager.authorize(request);

        verify(clientCredentialsClient, times(2)).getTokenResponse(any(OAuth2ClientCredentialsGrantRequest.class));
    }

    /**
     * Verifies that the exchange sends the user's token as subject and the client's own token as actor, and caches
     * the result under the user.
     */
    @Test
    void serviceClientAuthorizedClientManager_whenExchanging_sendsSubjectAndActorToken() {
        when(tokenClients.clientCredentials()).thenReturn(clientCredentialsClient);
        when(clientCredentialsClient.getTokenResponse(any())).thenReturn(response("cc-token", LONG_LIFETIME_SECONDS));
        final var sent = ArgumentCaptor.<TokenExchangeGrantRequest>captor();
        when(tokenExchangeClient.getTokenResponse(sent.capture()))
                .thenReturn(response("exchanged", LONG_LIFETIME_SECONDS));
        final var manager = manager();
        final var request = OAuth2AuthorizeRequest
                .withClientRegistrationId(ServiceClientRegistrationMapper.TOKEN_EXCHANGE_REGISTRATION_ID)
                .principal(principalMapper.user("user-token"))
                .build();

        final var first = manager.authorize(request);
        final var second = manager.authorize(request);

        assertEquals("exchanged", first.getAccessToken().getTokenValue());
        assertSame(first.getAccessToken(), second.getAccessToken());
        assertEquals("user-token", sent.getValue().getSubjectToken().getTokenValue());
        assertEquals("cc-token", sent.getValue().getActorToken().getTokenValue());
        verify(tokenExchangeClient, times(1)).getTokenResponse(any(TokenExchangeGrantRequest.class));
    }

    /**
     * Verifies that the DPoP key is generated and signs a proof.
     *
     * @throws Exception if the key cannot be generated.
     */
    @Test
    void serviceClientDPoPProofs_whenCalled_createsProofs() throws Exception {
        final var proofs = configuration.serviceClientDPoPProofs();

        assertNotNull(proofs.proof("POST", URI.create("https://auth.example.com/oauth2/token")));
    }

    /**
     * Verifies that the documents client of the service client is built for its own registration and principal.
     */
    @Test
    void serviceClientDocumentsApi_whenCalled_buildsTheClientOfTheClientCredentialsRegistration() {
        when(documentsApis.forPrincipal(any(String.class), any())).thenReturn(documentsApi);

        final var api = configuration.serviceClientDocumentsApi(documentsApis, principalMapper, properties());

        assertSame(documentsApi, api);
        verify(documentsApis).forPrincipal(
                eq(ServiceClientRegistrationMapper.CLIENT_CREDENTIALS_REGISTRATION_ID), any());
    }

    /**
     * Builds the settings.
     *
     * @return the settings.
     */
    private static ServiceClientAuthProperties properties() {
        return new ServiceClientAuthProperties(null, "client", "secret", null, null, REFRESH_BEFORE, false, null);
    }

    /**
     * Builds the registrations.
     *
     * @return the repository.
     */
    private ClientRegistrationRepository registrations() {
        return configuration.serviceClientRegistrations(new ServiceClientRegistrationMapper(), properties());
    }

    /**
     * Builds the authorized client manager over mocked token endpoint clients.
     *
     * @return the manager.
     */
    private OAuth2AuthorizedClientManager manager() {
        lenient().when(tokenClients.tokenExchange()).thenReturn(tokenExchangeClient);
        final var registrations = registrations();
        return configuration.serviceClientAuthorizedClientManager(registrations,
                configuration.serviceClientAuthorizedClients(registrations), tokenClients, principalMapper,
                properties());
    }

    /**
     * Builds the request for a client credentials token of the service client.
     *
     * @return the request.
     */
    private OAuth2AuthorizeRequest clientCredentialsRequest() {
        return OAuth2AuthorizeRequest
                .withClientRegistrationId(ServiceClientRegistrationMapper.CLIENT_CREDENTIALS_REGISTRATION_ID)
                .principal(principalMapper.serviceClient("client"))
                .build();
    }

    /**
     * Builds an answer of the token endpoint.
     *
     * @param value     value of the access token.
     * @param expiresIn lifetime of the token, in seconds.
     * @return the answer.
     */
    private static OAuth2AccessTokenResponse response(final String value, final long expiresIn) {
        return OAuth2AccessTokenResponse.withToken(value)
                .tokenType(OAuth2AccessToken.TokenType.BEARER)
                .expiresIn(expiresIn)
                .build();
    }
}
