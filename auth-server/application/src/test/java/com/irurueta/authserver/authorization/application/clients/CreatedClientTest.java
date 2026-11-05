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

import java.util.List;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link CreatedClient}.
 */
class CreatedClientTest {

    /** Redirect URI of the default clients built by the tests. */
    private static final String TEST_REDIRECT_URI = "https://app.example.test/callback";

    /** Clear-text secret used by the tests; not a real credential. */
    private static final String SECRET = "super-secret-value";

    /**
     * Verifies that the secret is kept but never printed.
     */
    @Test
    void toString_whenSecretIsSet_doesNotContainIt() {
        final var created = new CreatedClient(bff(), SECRET);

        assertEquals(SECRET, created.clientSecret());
        assertFalse(created.toString().contains(SECRET));
    }

    /**
     * Builds the default {@code bff} client with a test redirect URI.
     *
     * @return the client.
     */
    private static ClientRegistration bff() {
        return DefaultClientDefinitions.bff(List.of(TEST_REDIRECT_URI), DefaultClientDefinitions.DEFAULT_API_AUDIENCE);
    }
}
