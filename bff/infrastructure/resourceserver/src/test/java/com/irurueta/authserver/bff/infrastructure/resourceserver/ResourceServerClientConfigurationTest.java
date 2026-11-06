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

package com.irurueta.authserver.bff.infrastructure.resourceserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import java.net.URI;
import java.time.Instant;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

/**
 * Unit tests of {@link ResourceServerClientConfiguration}.
 */
@ExtendWith(MockitoExtension.class)
class ResourceServerClientConfigurationTest {

    /** Base URI of the resource server in the tests, with a trailing slash the configuration must drop. */
    private static final String BASE_URI = "http://resource:9090/";

    /** URL of the documents. */
    private static final String URL = "http://resource:9090/api/documents";

    /** Token the manager hands out. */
    private static final String TOKEN = "test-access-token";

    /** Seconds the token of the tests lives. */
    private static final long TOKEN_SECONDS = 60;

    /** Manager of the authorized clients. */
    @Mock
    private OAuth2AuthorizedClientManager manager;

    /** Builder the client is made from. */
    private RestClient.Builder builder;

    /** Server standing in for the resource server. */
    private MockRestServiceServer server;

    /** Configuration under test. */
    private final ResourceServerClientConfiguration configuration = new ResourceServerClientConfiguration();

    /**
     * Signs a user in and binds a mock server to the builder.
     */
    @BeforeEach
    void setUp() {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("user", "n/a"));
        builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
    }

    /**
     * Clears the security context.
     */
    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    /**
     * Verifies that the access token of the {@code bff} registration is sent as bearer token.
     */
    @Test
    void resourceServerRestClient_whenTokenIsAvailable_sendsBearerToken() {
        authorizeWithToken();
        server.expect(requestTo(URL)).andExpect(header("Authorization", "Bearer " + TOKEN))
                .andRespond(withSuccess());

        final var client = configuration.resourceServerRestClient(builder, manager);

        client.get().uri(URL).retrieve().toBodilessEntity();

        server.verify();
    }

    /**
     * Verifies that a failure to obtain or renew the token surfaces as an authorization exception.
     */
    @Test
    void resourceServerRestClient_whenTokenCannotBeRenewed_throwsAuthorizationException() {
        when(manager.authorize(any(OAuth2AuthorizeRequest.class)))
                .thenThrow(new ClientAuthorizationException(new OAuth2Error("invalid_grant"), "bff"));
        final var client = configuration.resourceServerRestClient(builder, manager);

        assertThrows(ClientAuthorizationException.class, () -> client.get().uri(URL).retrieve().toBodilessEntity());
    }

    /**
     * Verifies that a session without authorized client never sends the call upstream.
     */
    @Test
    void resourceServerRestClient_whenSessionHasNoAuthorizedClient_throwsAuthorizationException() {
        when(manager.authorize(any(OAuth2AuthorizeRequest.class))).thenReturn(null);
        final var client = configuration.resourceServerRestClient(builder, manager);

        assertThrows(ClientAuthorizationException.class, () -> client.get().uri(URL).retrieve().toBodilessEntity());
        server.verify();
    }

    /**
     * Verifies that the generated documents client calls the configured resource server through the REST client
     * that carries the user's token.
     */
    @Test
    void resourceServerDocumentsApi_whenListing_callsTheConfiguredBaseUriWithTheToken() {
        authorizeWithToken();
        server.expect(requestTo(URL)).andExpect(header("Authorization", "Bearer " + TOKEN))
                .andRespond(withSuccess("[{\"id\":\"1\",\"owner\":\"alice\",\"title\":\"T\",\"content\":\"C\"}]",
                        MediaType.APPLICATION_JSON));
        final var restClient = configuration.resourceServerRestClient(builder, manager);

        final var documents = configuration.resourceServerDocumentsApi(restClient,
                new ResourceServerProperties(URI.create(BASE_URI))).listDocuments();

        server.verify();
        assertEquals("alice", documents.getFirst().getOwner());
    }

    /**
     * Makes the manager hand out the test token for the {@code bff} registration.
     */
    private void authorizeWithToken() {
        final var registration = ClientRegistration
                .withRegistrationId(ResourceServerClientConfiguration.REGISTRATION_ID)
                .clientId("bff").authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost/cb").authorizationUri("http://as/authorize")
                .tokenUri("http://as/token").build();
        final var token = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, TOKEN, Instant.now(),
                Instant.now().plusSeconds(TOKEN_SECONDS));
        when(manager.authorize(any(OAuth2AuthorizeRequest.class)))
                .thenReturn(new OAuth2AuthorizedClient(registration, "user", token));
    }
}
