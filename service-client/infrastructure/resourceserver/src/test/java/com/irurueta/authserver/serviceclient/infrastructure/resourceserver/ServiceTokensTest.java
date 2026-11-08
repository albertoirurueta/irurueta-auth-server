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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.serviceclient.domain.documents.DocumentAccessException;
import java.time.Instant;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * Unit tests of {@link ServiceTokens}.
 */
@ExtendWith(MockitoExtension.class)
class ServiceTokensTest {

    /** Lifetime of the token, in seconds. */
    private static final long LIFETIME_SECONDS = 300L;

    /** Obtains and renews the access tokens. */
    @Mock
    private OAuth2AuthorizedClientManager manager;

    /** Builds the principals; the real one. */
    @Spy
    private PrincipalMapper principalMapper;

    /** Settings of the service client. */
    private final ServiceClientAuthProperties properties =
            new ServiceClientAuthProperties(null, "client", null, null, null, null, false, null);

    /** Object under test. */
    private ServiceTokens tokens;

    /**
     * Creates the object under test.
     */
    @BeforeEach
    void setUp() {
        tokens = new ServiceTokens(manager, principalMapper, properties);
    }

    /**
     * Verifies that the client credentials token is the one of the client's own registration and principal.
     */
    @Test
    void clientCredentialsToken_whenManagerAuthorizes_returnsTheTokenValue() {
        final var asked = ArgumentCaptor.<OAuth2AuthorizeRequest>captor();
        when(manager.authorize(asked.capture())).thenReturn(authorizedClient("cc-token"));

        assertEquals("cc-token", tokens.clientCredentialsToken());

        assertEquals(ServiceClientRegistrationMapper.CLIENT_CREDENTIALS_REGISTRATION_ID,
                asked.getValue().getClientRegistrationId());
        assertEquals("client", asked.getValue().getPrincipal().getName());
    }

    /**
     * Verifies that the exchanged token is asked for the token exchange registration with the user as principal.
     */
    @Test
    void exchangedToken_whenManagerAuthorizes_returnsTheTokenValue() {
        final var asked = ArgumentCaptor.<OAuth2AuthorizeRequest>captor();
        when(manager.authorize(asked.capture())).thenReturn(authorizedClient("exchanged"));

        assertEquals("exchanged", tokens.exchangedToken("user-token"));

        assertEquals(ServiceClientRegistrationMapper.TOKEN_EXCHANGE_REGISTRATION_ID,
                asked.getValue().getClientRegistrationId());
        verify(principalMapper).user("user-token");
    }

    /**
     * Verifies that a manager that has no token is reported as an access failure.
     */
    @Test
    void clientCredentialsToken_whenManagerReturnsNull_throwsDocumentAccessException() {
        when(manager.authorize(any(OAuth2AuthorizeRequest.class))).thenReturn(null);

        assertThrows(DocumentAccessException.class, () -> tokens.clientCredentialsToken());
    }

    /**
     * Verifies that a refused token request is reported as an access failure carrying the cause.
     */
    @Test
    void exchangedToken_whenExchangeIsRefused_throwsDocumentAccessException() {
        final var failure = new ClientAuthorizationException(new OAuth2Error("invalid_grant"), "id");
        when(manager.authorize(any(OAuth2AuthorizeRequest.class))).thenThrow(failure);

        final var error = assertThrows(DocumentAccessException.class, () -> tokens.exchangedToken("user-token"));

        assertSame(failure, error.getCause());
    }

    /**
     * Builds an authorized client.
     *
     * @param value value of its token.
     * @return the authorized client.
     */
    private static OAuth2AuthorizedClient authorizedClient(final String value) {
        final var now = Instant.now();
        final var registration = new ServiceClientRegistrationMapper().clientCredentials(
                new ServiceClientAuthProperties(null, null, null, null, null, null, false, null));
        return new OAuth2AuthorizedClient(registration, "name", new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, value, now, now.plusSeconds(LIFETIME_SECONDS)));
    }
}
