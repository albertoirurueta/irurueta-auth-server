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
package com.irurueta.authserver.authorization.domain.social;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link IdentityProvider}.
 */
class IdentityProviderTest {

    /** Number of providers supported. */
    private static final int PROVIDERS = 4;

    /**
     * Verifies that the four providers have their lower case registration ids.
     */
    @Test
    void id_whenProviderIsKnown_isLowerCaseRegistrationId() {
        assertEquals(PROVIDERS, IdentityProvider.values().length);
        assertEquals("google", IdentityProvider.GOOGLE.id());
        assertEquals("microsoft", IdentityProvider.MICROSOFT.id());
        assertEquals("apple", IdentityProvider.APPLE.id());
        assertEquals("github", IdentityProvider.GITHUB.id());
    }

    /**
     * Verifies that every provider is found by its own id.
     */
    @Test
    void fromId_whenIdIsKnown_returnsProvider() {
        for (final var provider : IdentityProvider.values()) {
            assertEquals(provider, IdentityProvider.fromId(provider.id()).orElseThrow());
        }
    }

    /**
     * Verifies that an unknown id has no provider.
     */
    @Test
    void fromId_whenIdIsUnknown_returnsEmpty() {
        assertTrue(IdentityProvider.fromId("facebook").isEmpty());
        assertTrue(IdentityProvider.fromId("GOOGLE").isEmpty());
    }

    /**
     * Verifies that a missing id has no provider.
     */
    @Test
    void fromId_whenIdIsNull_returnsEmpty() {
        assertTrue(IdentityProvider.fromId(null).isEmpty());
    }
}
