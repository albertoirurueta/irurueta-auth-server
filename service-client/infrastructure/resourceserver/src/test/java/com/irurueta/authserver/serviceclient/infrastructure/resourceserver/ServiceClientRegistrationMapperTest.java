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

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

/**
 * Unit tests of {@link ServiceClientRegistrationMapper}.
 */
class ServiceClientRegistrationMapperTest {

    /** Settings used by the tests. */
    private static final ServiceClientAuthProperties PROPERTIES = new ServiceClientAuthProperties(
            AuthMethod.PRIVATE_KEY_JWT, "client", "secret", URI.create("https://auth.example.com/oauth2/token"),
            List.of("documents.read", "documents.delete"), Duration.ofSeconds(1), false, null);

    /** Mapper under test. */
    private final ServiceClientRegistrationMapper mapper = new ServiceClientRegistrationMapper();

    /**
     * Verifies the registration of the client credentials grant.
     */
    @Test
    void clientCredentials_whenCalled_buildsTheRegistrationFromTheSettings() {
        final var registration = mapper.clientCredentials(PROPERTIES);

        assertEquals(ServiceClientRegistrationMapper.CLIENT_CREDENTIALS_REGISTRATION_ID,
                registration.getRegistrationId());
        assertEquals(AuthorizationGrantType.CLIENT_CREDENTIALS, registration.getAuthorizationGrantType());
        assertEquals(ClientAuthenticationMethod.PRIVATE_KEY_JWT, registration.getClientAuthenticationMethod());
        assertEquals("client", registration.getClientId());
        assertEquals("secret", registration.getClientSecret());
        assertEquals("https://auth.example.com/oauth2/token", registration.getProviderDetails().getTokenUri());
        assertEquals(Set.of("documents.read", "documents.delete"), registration.getScopes());
    }

    /**
     * Verifies that the token exchange registration only differs in id and grant type.
     */
    @Test
    void tokenExchange_whenCalled_buildsTheRegistrationWithTheExchangeGrant() {
        final var registration = mapper.tokenExchange(PROPERTIES);

        assertEquals(ServiceClientRegistrationMapper.TOKEN_EXCHANGE_REGISTRATION_ID, registration.getRegistrationId());
        assertEquals(AuthorizationGrantType.TOKEN_EXCHANGE, registration.getAuthorizationGrantType());
        assertEquals("client", registration.getClientId());
        assertEquals(ClientAuthenticationMethod.PRIVATE_KEY_JWT, registration.getClientAuthenticationMethod());
    }
}
