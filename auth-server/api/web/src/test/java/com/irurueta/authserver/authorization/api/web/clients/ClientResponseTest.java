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

package com.irurueta.authserver.authorization.api.web.clients;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.irurueta.authserver.authorization.application.clients.DefaultClientDefinitions;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link ClientResponse}.
 */
class ClientResponseTest {

    /**
     * Mapping keeps every field of the registration.
     */
    @Test
    void from_whenRegistrationGiven_mapsFields() {
        final var registration = DefaultClientDefinitions.bff();

        final var response = ClientResponse.from(registration);

        assertEquals(registration.clientId(), response.clientId());
        assertEquals(registration.name(), response.name());
        assertEquals(registration.confidential(), response.confidential());
        assertEquals(registration.authMethods(), response.authMethods());
        assertEquals(registration.grantTypes(), response.grantTypes());
        assertEquals(registration.redirectUris(), response.redirectUris());
        assertEquals(registration.scopes(), response.scopes());
        assertEquals(registration.requireProofKey(), response.requireProofKey());
        assertEquals(registration.audiences(), response.audiences());
        assertEquals(registration.accessTokenTtl(), response.accessTokenTtl());
        assertEquals(registration.refreshTokenTtl(), response.refreshTokenTtl());
        assertEquals(registration.accessTokenFormat(), response.accessTokenFormat());
        assertEquals(registration.reuseRefreshTokens(), response.reuseRefreshTokens());
    }
}
