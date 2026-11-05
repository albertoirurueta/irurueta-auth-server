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

package com.irurueta.authserver.authorization.application.clients;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link DefaultClientDefinitions}.
 */
class DefaultClientDefinitionsTest {

    /**
     * Verifies that the BFF is a confidential client with rotation on.
     */
    @Test
    void bff_whenCalled_isConfidentialWithPkceAndRotation() {
        final var bff = DefaultClientDefinitions.bff();

        assertEquals(DefaultClientDefinitions.BFF_CLIENT_ID, bff.clientId());
        assertTrue(bff.confidential());
        assertEquals(List.of("client_secret_basic"), bff.authMethods());
        assertEquals(List.of("authorization_code", "refresh_token"), bff.grantTypes());
        assertTrue(bff.requireProofKey());
        assertFalse(bff.reuseRefreshTokens());
        assertEquals(List.of(DefaultClientDefinitions.RESOURCE_SERVER_AUDIENCE), bff.audiences());
    }

    /**
     * Verifies that the SPA is a public client without client authentication.
     */
    @Test
    void spaPublic_whenCalled_isPublicWithPkce() {
        final var spa = DefaultClientDefinitions.spaPublic();

        assertEquals(DefaultClientDefinitions.SPA_PUBLIC_CLIENT_ID, spa.clientId());
        assertFalse(spa.confidential());
        assertEquals(List.of("none"), spa.authMethods());
        assertTrue(spa.requireProofKey());
    }

    /**
     * Verifies that both default clients are listed.
     */
    @Test
    void all_whenCalled_listsBothClients() {
        assertEquals(List.of(DefaultClientDefinitions.bff(), DefaultClientDefinitions.spaPublic()),
                DefaultClientDefinitions.all());
    }
}
