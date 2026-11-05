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

import java.util.UUID;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link ClientSeedProperties}.
 */
class ClientSeedPropertiesTest {

    /**
     * The secret is kept but never printed.
     */
    @Test
    void toString_whenCalled_hidesSecret() {
        final var secret = UUID.randomUUID().toString();

        final var properties = new ClientSeedProperties(secret);

        assertEquals(secret, properties.bffSecret());
        assertFalse(properties.toString().contains(secret));
    }
}
