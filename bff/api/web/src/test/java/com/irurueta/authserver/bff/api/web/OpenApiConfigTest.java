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

package com.irurueta.authserver.bff.api.web;

import static org.junit.jupiter.api.Assertions.assertEquals;

import io.swagger.v3.oas.models.security.SecurityScheme;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link OpenApiConfig}.
 */
class OpenApiConfigTest {

    /** Configuration under test. */
    private final OpenApiConfig config = new OpenApiConfig();

    /**
     * Verifies that the document describes the API and declares the session-cookie scheme.
     */
    @Test
    void bffOpenApi_whenCalled_declaresTheSessionScheme() {
        final var openApi = config.bffOpenApi();
        final var scheme = openApi.getComponents().getSecuritySchemes().get(OpenApiConfig.SESSION_SCHEME);

        assertEquals("Irurueta BFF API", openApi.getInfo().getTitle());
        assertEquals(SecurityScheme.Type.APIKEY, scheme.getType());
        assertEquals(SecurityScheme.In.COOKIE, scheme.getIn());
        assertEquals(OpenApiConfig.SESSION_COOKIE, scheme.getName());
    }

    /**
     * Verifies that the API group matches only the BFF's own JSON paths.
     */
    @Test
    void apiGroup_whenCalled_matchesOnlyBffPaths() {
        final var group = config.apiGroup();

        assertEquals("api", group.getGroup());
        assertEquals(List.of("/bff/**"), group.getPathsToMatch());
    }
}
