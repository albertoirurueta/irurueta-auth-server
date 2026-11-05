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

import com.irurueta.authserver.authorization.application.clients.CreatedClient;
import com.irurueta.authserver.authorization.application.clients.DefaultClientDefinitions;
import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link CreatedClientResponse}.
 */
class CreatedClientResponseTest {

    /**
     * The response carries the secret but never prints it.
     */
    @Test
    void from_whenSecretGiven_keepsSecretAndHidesItInToString() {
        final var secret = UUID.randomUUID().toString();

        final var response = CreatedClientResponse.from(new CreatedClient(DefaultClientDefinitions.bff(), secret));

        assertEquals(secret, response.clientSecret());
        assertEquals("bff", response.client().clientId());
        assertFalse(response.toString().contains(secret));
    }
}
