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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.file.Path;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link ServiceClientKeyProperties}.
 */
class ServiceClientKeyPropertiesTest {

    /** Inline key text. */
    private static final String PEM = "-----BEGIN PRIVATE KEY-----secret-----END PRIVATE KEY-----";

    /**
     * Verifies that the description never shows the key but does show where it comes from.
     */
    @Test
    void toString_whenKeyIsInline_doesNotContainIt() {
        final var properties = new ServiceClientKeyProperties(PEM, Path.of("key.pem"), "kid-1");

        assertFalse(properties.toString().contains("secret"));
        assertTrue(properties.toString().contains("key.pem"));
        assertTrue(properties.toString().contains("kid-1"));
    }
}
