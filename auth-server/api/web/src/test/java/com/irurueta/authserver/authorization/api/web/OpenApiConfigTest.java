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

package com.irurueta.authserver.authorization.api.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link OpenApiConfig}.
 */
class OpenApiConfigTest {

    /** Configuration under test. */
    private final OpenApiConfig config = new OpenApiConfig();

    /**
     * Verifies that the OpenAPI document describes the API.
     */
    @Test
    void authServerOpenApi_whenCalled_describesTheApi() {
        final var info = config.authServerOpenApi().getInfo();

        assertEquals("Irurueta Auth Server API", info.getTitle());
        assertFalse(info.getVersion().isBlank());
        assertEquals("Apache License 2.0", info.getLicense().getName());
    }

    /**
     * Verifies that the API group matches only the application's own API paths.
     */
    @Test
    void apiGroup_whenCalled_matchesOnlyApiPaths() {
        final var group = config.apiGroup();

        assertEquals("api", group.getGroup());
        assertEquals(List.of("/api/**"), group.getPathsToMatch());
    }
}
