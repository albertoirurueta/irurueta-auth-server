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
package com.irurueta.authserver.authorization.api.web.implicit;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * Unit tests of {@link DeviceClientAuthenticationProvider}.
 */
@ExtendWith(MockitoExtension.class)
class DeviceClientAuthenticationProviderTest {

    /** Identifier of the client. */
    private static final String CLIENT_ID = "device-client";

    /** Finds the registered clients. */
    @Mock
    private RegisteredClientRepository registeredClientRepository;

    /** Provider under test. */
    @InjectMocks
    private DeviceClientAuthenticationProvider provider;

    /**
     * Verifies that a registered public client is authenticated.
     */
    @Test
    void authenticate_whenTheClientIsPublic_returnsTheAuthenticatedClient() {
        final var client = client(ClientAuthenticationMethod.NONE);
        when(registeredClientRepository.findByClientId(CLIENT_ID)).thenReturn(client);

        final var result = assertInstanceOf(OAuth2ClientAuthenticationToken.class,
                provider.authenticate(new DeviceClientAuthenticationToken(CLIENT_ID)));

        assertEquals(client, result.getRegisteredClient());
        assertTrue(result.isAuthenticated());
    }

    /**
     * Verifies that an unknown client is refused.
     */
    @Test
    void authenticate_whenTheClientIsUnknown_throwsInvalidClient() {
        final var error = assertThrows(OAuth2AuthenticationException.class,
                () -> provider.authenticate(new DeviceClientAuthenticationToken(CLIENT_ID)));

        assertEquals("invalid_client", error.getError().getErrorCode());
    }

    /**
     * Verifies that a confidential client, which did not register the {@code none} method, is refused.
     */
    @Test
    void authenticate_whenTheClientIsConfidential_throwsInvalidClient() {
        when(registeredClientRepository.findByClientId(CLIENT_ID))
                .thenReturn(client(ClientAuthenticationMethod.CLIENT_SECRET_BASIC));

        final var error = assertThrows(OAuth2AuthenticationException.class,
                () -> provider.authenticate(new DeviceClientAuthenticationToken(CLIENT_ID)));

        assertEquals("invalid_client", error.getError().getErrorCode());
    }

    /**
     * Verifies that only the requests of the device flow are supported, never a PKCE one.
     */
    @Test
    void supports_whenTheTypeIsNotTheDeviceFlows_returnsFalse() {
        assertTrue(provider.supports(DeviceClientAuthenticationToken.class));
        assertFalse(provider.supports(OAuth2ClientAuthenticationToken.class));
    }

    /**
     * Builds a client.
     *
     * @param method its authentication method.
     * @return the client.
     */
    private static RegisteredClient client(final ClientAuthenticationMethod method) {
        return RegisteredClient.withId("1").clientId(CLIENT_ID).clientAuthenticationMethod(method)
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE).build();
    }
}
