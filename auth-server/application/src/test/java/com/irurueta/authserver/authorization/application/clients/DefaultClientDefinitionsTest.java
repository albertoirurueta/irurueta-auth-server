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

    /** Redirect URI given to the definitions. */
    private static final String REDIRECT_URI = "https://app.example.test/callback";

    /** Audience of the authorization server's API given to the definitions. */
    private static final String API_AUDIENCE = "custom-api";

    /** Scopes both default clients must carry. */
    private static final List<String> SCOPES = List.of("openid", "profile", "documents.read", "documents.delete");

    /**
     * Verifies that the BFF is a confidential client with rotation on, the given redirect URIs and both audiences.
     */
    @Test
    void bff_whenCalled_isConfidentialWithPkceAndRotation() {
        final var bff = DefaultClientDefinitions.bff(List.of(REDIRECT_URI), API_AUDIENCE);

        assertEquals(DefaultClientDefinitions.BFF_CLIENT_ID, bff.clientId());
        assertTrue(bff.confidential());
        assertEquals(List.of("client_secret_basic"), bff.authMethods());
        assertEquals(List.of("authorization_code", "refresh_token"), bff.grantTypes());
        assertTrue(bff.requireProofKey());
        assertFalse(bff.reuseRefreshTokens());
        assertEquals(List.of(REDIRECT_URI), bff.redirectUris());
        assertEquals(List.of(DefaultClientDefinitions.RESOURCE_SERVER_AUDIENCE, API_AUDIENCE), bff.audiences());
    }

    /**
     * Verifies that the SPA is a public client without client authentication, the given redirect URIs and both
     * audiences.
     */
    @Test
    void spaPublic_whenCalled_isPublicWithPkce() {
        final var spa = DefaultClientDefinitions.spaPublic(List.of(REDIRECT_URI), API_AUDIENCE);

        assertEquals(DefaultClientDefinitions.SPA_PUBLIC_CLIENT_ID, spa.clientId());
        assertFalse(spa.confidential());
        assertEquals(List.of("none"), spa.authMethods());
        assertTrue(spa.requireProofKey());
        assertEquals(List.of(REDIRECT_URI), spa.redirectUris());
        assertEquals(List.of(DefaultClientDefinitions.RESOURCE_SERVER_AUDIENCE, API_AUDIENCE), spa.audiences());
    }

    /**
     * Verifies that both clients may read and delete documents and never get the {@code admin} scope.
     */
    @Test
    void scopes_whenDefined_includeTheDocumentScopesButNotAdmin() {
        final var bff = DefaultClientDefinitions.bff(List.of(REDIRECT_URI), API_AUDIENCE);
        final var spa = DefaultClientDefinitions.spaPublic(List.of(REDIRECT_URI), API_AUDIENCE);

        assertEquals(SCOPES, bff.scopes());
        assertEquals(SCOPES, spa.scopes());
        assertFalse(bff.scopes().contains("admin"));
        assertFalse(spa.scopes().contains("admin"));
    }
}
