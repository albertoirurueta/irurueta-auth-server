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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link ServiceClientAuthProperties}.
 */
class ServiceClientAuthPropertiesTest {

    /** A shared secret. */
    private static final String SECRET = "very-secret-value";

    /** A configured token endpoint. */
    private static final URI TOKEN_URI = URI.create("https://auth.example.com/oauth2/token");

    /**
     * Verifies every default.
     */
    @Test
    void constructor_whenNothingIsConfigured_appliesTheDefaults() {
        final var properties = empty();

        assertEquals(AuthMethod.CLIENT_SECRET_BASIC, properties.method());
        assertEquals("service-client", properties.clientId());
        assertEquals("", properties.clientSecret());
        assertEquals(URI.create("http://localhost:9000/oauth2/token"), properties.tokenUri());
        assertEquals(List.of("documents.read"), properties.scopes());
        assertEquals(Duration.ofSeconds(ServiceClientAuthProperties.DEFAULT_REFRESH_BEFORE_SECONDS),
                properties.refreshBefore());
        assertFalse(properties.dpop());
    }

    /**
     * Verifies that blank identifiers and empty scope lists are replaced by the defaults.
     */
    @Test
    void constructor_whenClientIdIsBlankAndScopesEmpty_appliesTheDefaults() {
        final var properties = new ServiceClientAuthProperties(null, " ", null, null, List.of(), null, false, null);

        assertEquals(ServiceClientAuthProperties.DEFAULT_CLIENT_ID, properties.clientId());
        assertEquals(List.of(ServiceClientAuthProperties.DEFAULT_SCOPE), properties.scopes());
    }

    /**
     * Verifies that configured values are kept.
     */
    @Test
    void constructor_whenValuesAreGiven_keepsThem() {
        final var properties = new ServiceClientAuthProperties(AuthMethod.PRIVATE_KEY_JWT, "client", SECRET, TOKEN_URI,
                List.of("a", "b"), Duration.ZERO, true, "bundle");

        assertEquals(AuthMethod.PRIVATE_KEY_JWT, properties.method());
        assertEquals("client", properties.clientId());
        assertEquals(SECRET, properties.clientSecret());
        assertEquals(TOKEN_URI, properties.tokenUri());
        assertEquals(List.of("a", "b"), properties.scopes());
        assertEquals(Duration.ZERO, properties.refreshBefore());
        assertTrue(properties.dpop());
        assertEquals("bundle", properties.sslBundle());
    }

    /**
     * Verifies that a negative refresh margin is refused.
     */
    @Test
    void constructor_whenRefreshBeforeIsNegative_throwsIllegalArgumentException() {
        final var negative = Duration.ofSeconds(-1);

        assertThrows(IllegalArgumentException.class,
                () -> new ServiceClientAuthProperties(null, null, null, null, null, negative, false, null));
    }

    /**
     * Verifies that the description never shows the secret.
     */
    @Test
    void toString_whenSecretIsSet_doesNotContainIt() {
        final var properties = new ServiceClientAuthProperties(null, null, SECRET, null, null, null, false, null);

        assertFalse(properties.toString().contains(SECRET));
        assertTrue(properties.toString().contains("service-client"));
    }

    /**
     * Creates properties with nothing configured.
     *
     * @return the properties.
     */
    private static ServiceClientAuthProperties empty() {
        return new ServiceClientAuthProperties(null, null, null, null, null, null, false, null);
    }
}
