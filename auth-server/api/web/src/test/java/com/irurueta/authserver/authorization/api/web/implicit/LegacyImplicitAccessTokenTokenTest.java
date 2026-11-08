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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

/**
 * Unit tests of {@link LegacyImplicitAccessTokenToken}.
 */
class LegacyImplicitAccessTokenTokenTest {

    /** Redirect URI. */
    private static final String REDIRECT_URI = "http://localhost:9000/legacy-implicit/";

    /** Lifetime of the token in seconds. */
    private static final long LIFETIME = 300;

    /**
     * Verifies that the token exposes the access token and the data of the response and is authenticated.
     */
    @Test
    void constructor_whenCreated_exposesTheResult() {
        final var now = Instant.now();
        final var accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "value", now,
                now.plusSeconds(LIFETIME), Set.of("documents.read"));

        final var token = new LegacyImplicitAccessTokenToken(accessToken, Set.of("documents.read"), REDIRECT_URI,
                "abc");

        assertSame(accessToken, token.getAccessToken());
        assertEquals(Set.of("documents.read"), token.getScopes());
        assertEquals(REDIRECT_URI, token.getRedirectUri());
        assertEquals("abc", token.getState());
        assertEquals(REDIRECT_URI, token.getPrincipal());
        assertEquals("", token.getCredentials());
        assertTrue(token.isAuthenticated());
    }
}
