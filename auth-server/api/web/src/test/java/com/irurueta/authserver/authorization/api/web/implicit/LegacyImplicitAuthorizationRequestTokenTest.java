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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.authentication.TestingAuthenticationToken;

/**
 * Unit tests of {@link LegacyImplicitAuthorizationRequestToken}.
 */
class LegacyImplicitAuthorizationRequestTokenTest {

    /** Client id. */
    private static final String CLIENT_ID = "legacy-implicit-spa";

    /** Redirect URI. */
    private static final String REDIRECT_URI = "http://localhost:9000/legacy-implicit/";

    /** State. */
    private static final String STATE = "abc";

    /**
     * Verifies that the token exposes what the request carried and is not authenticated.
     */
    @Test
    void constructor_whenCreated_exposesTheRequest() {
        final Authentication user = new TestingAuthenticationToken("alice", "secret");

        final var token = new LegacyImplicitAuthorizationRequestToken(CLIENT_ID, REDIRECT_URI,
                Set.of("documents.read"), STATE, user);

        assertEquals(CLIENT_ID, token.getClientId());
        assertEquals(REDIRECT_URI, token.getRedirectUri());
        assertEquals(Set.of("documents.read"), token.getScopes());
        assertEquals(STATE, token.getState());
        assertSame(user, token.getPrincipal());
        assertEquals("", token.getCredentials());
        assertFalse(token.isAuthenticated());
    }

    /**
     * Verifies that a request without redirect URI or state keeps them {@code null}.
     */
    @Test
    void constructor_whenOptionalValuesAreMissing_keepsThemNull() {
        final var token = new LegacyImplicitAuthorizationRequestToken(CLIENT_ID, null, Set.of(), null,
                new TestingAuthenticationToken("alice", "secret"));

        assertNull(token.getRedirectUri());
        assertNull(token.getState());
    }
}
