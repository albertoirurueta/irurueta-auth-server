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

package com.irurueta.authserver.resourceserver.api.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.swagger.v3.oas.models.security.SecurityScheme;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link OpenApiConfig}.
 */
class OpenApiConfigTest {

    /** Subject under test. */
    private final OpenApiConfig config = new OpenApiConfig();

    /** The document declares the bearer scheme. */
    @Test
    void resourceServerOpenApi_whenBuilt_declaresTheBearerScheme() {
        final var openApi = config.resourceServerOpenApi();

        assertEquals(SecurityScheme.Type.HTTP,
                openApi.getComponents().getSecuritySchemes().get(OpenApiConfig.BEARER_SCHEME).getType());
        assertEquals("Irurueta Resource Server API", openApi.getInfo().getTitle());
    }

    /** The group only covers the API paths. */
    @Test
    void apiGroup_whenBuilt_matchesTheApiPaths() {
        final var group = config.apiGroup();

        assertEquals("api", group.getGroup());
        assertTrue(group.getPathsToMatch().contains("/api/**"));
    }
}
