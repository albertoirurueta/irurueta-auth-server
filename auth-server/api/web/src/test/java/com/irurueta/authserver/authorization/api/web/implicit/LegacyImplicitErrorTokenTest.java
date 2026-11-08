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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link LegacyImplicitErrorToken}.
 */
class LegacyImplicitErrorTokenTest {

    /** Redirect URI. */
    private static final String REDIRECT_URI = "http://localhost:9000/legacy-implicit/";

    /**
     * Verifies that the token carries the refusal and is marked authenticated so the endpoint answers it.
     */
    @Test
    void constructor_whenCreated_exposesTheRefusal() {
        final var token = new LegacyImplicitErrorToken("invalid_scope", "no", REDIRECT_URI, "abc");

        assertEquals("invalid_scope", token.getError());
        assertEquals("no", token.getDescription());
        assertEquals(REDIRECT_URI, token.getRedirectUri());
        assertEquals("abc", token.getState());
        assertEquals("invalid_scope", token.getPrincipal());
        assertEquals("", token.getCredentials());
        assertTrue(token.isAuthenticated());
    }

    /**
     * Verifies that the description and the state may be absent.
     */
    @Test
    void constructor_whenOptionalValuesAreMissing_keepsThemNull() {
        final var token = new LegacyImplicitErrorToken("invalid_request", null, REDIRECT_URI, null);

        assertNull(token.getDescription());
        assertNull(token.getState());
    }
}
