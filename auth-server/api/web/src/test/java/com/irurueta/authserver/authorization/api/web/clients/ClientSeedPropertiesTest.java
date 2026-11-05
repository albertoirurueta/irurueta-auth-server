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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.api.web.clients.ClientSeedProperties.SeededClient;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link ClientSeedProperties}.
 */
class ClientSeedPropertiesTest {

    /** Redirect URI used by the tests. */
    private static final String REDIRECT_URI = "https://bff.example.test/login/oauth2/code/bff";

    /**
     * The secret is kept but never printed.
     */
    @Test
    void toString_whenCalled_hidesSecret() {
        final var secret = UUID.randomUUID().toString();

        final var properties = new ClientSeedProperties(secret, null, null);

        assertEquals(secret, properties.bffSecret());
        assertFalse(properties.toString().contains(secret));
    }

    /**
     * Missing client sections become unconfigured ones, so nothing is seeded by default.
     */
    @Test
    void constructor_whenClientSectionsAreMissing_leavesBothUnconfigured() {
        final var properties = new ClientSeedProperties(null, null, null);

        assertFalse(properties.bff().isConfigured());
        assertFalse(properties.spaPublic().isConfigured());
    }

    /**
     * A client with redirect URIs is configured, and its list is a defensive copy.
     */
    @Test
    void seededClient_whenRedirectUrisAreGiven_isConfiguredWithACopy() {
        final var uris = new ArrayList<>(List.of(REDIRECT_URI));

        final var client = new SeededClient(uris);
        uris.clear();

        assertTrue(client.isConfigured());
        assertEquals(List.of(REDIRECT_URI), client.redirectUris());
        assertThrows(UnsupportedOperationException.class, () -> client.redirectUris().add(REDIRECT_URI));
    }

    /**
     * A client without a list of redirect URIs is not configured.
     */
    @Test
    void seededClient_whenRedirectUrisAreNull_isNotConfigured() {
        assertFalse(new SeededClient(null).isConfigured());
    }
}
