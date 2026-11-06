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

package com.irurueta.authserver.bff.infrastructure.resourceserver;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.URI;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link ResourceServerProperties}.
 */
class ResourceServerPropertiesTest {

    /** Base URI used by the tests. */
    private static final URI BASE_URI = URI.create("http://resource:9090");

    /**
     * Verifies that the configured base URI is kept.
     */
    @Test
    void constructor_whenBaseUriIsGiven_keepsIt() {
        assertEquals(BASE_URI, new ResourceServerProperties(BASE_URI).baseUri());
    }

    /**
     * Verifies that nothing configured falls back to the local resource server.
     */
    @Test
    void constructor_whenBaseUriIsMissing_usesLocalResourceServer() {
        assertEquals(URI.create("http://localhost:8081"), new ResourceServerProperties(null).baseUri());
    }
}
