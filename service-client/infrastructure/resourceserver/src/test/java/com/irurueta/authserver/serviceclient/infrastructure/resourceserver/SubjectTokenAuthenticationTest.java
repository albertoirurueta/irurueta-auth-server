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
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

/**
 * Unit tests of {@link SubjectTokenAuthentication}.
 */
class SubjectTokenAuthenticationTest {

    /** The user's token. */
    private static final OAuth2AccessToken TOKEN =
            new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "value", null, null);

    /**
     * Verifies that the principal is the token, which the exchange provider reads as the subject token, while the
     * name is the one given.
     */
    @Test
    void constructor_whenCreated_exposesTheTokenAsPrincipalAndTheGivenName() {
        final var authentication = new SubjectTokenAuthentication(TOKEN, "alice#1");

        assertSame(TOKEN, authentication.getPrincipal());
        assertSame(TOKEN, authentication.getCredentials());
        assertEquals("alice#1", authentication.getName());
        assertTrue(authentication.isAuthenticated());
        assertTrue(authentication.getAuthorities().isEmpty());
    }
}
