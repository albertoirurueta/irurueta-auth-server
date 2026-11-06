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

import io.swagger.v3.oas.models.OpenAPI;
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
     * Verifies that the document declares the bearer scheme the contract's operations refer to.
     */
    @Test
    void authServerOpenApi_whenCalled_declaresTheBearerScheme() {
        final var scheme = config.authServerOpenApi().getComponents().getSecuritySchemes()
                .get(OpenApiConfig.BEARER_SCHEME);

        assertEquals(SecurityScheme.Type.HTTP, scheme.getType());
        assertEquals("bearer", scheme.getScheme());
        assertEquals("JWT", scheme.getBearerFormat());
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

    /**
     * Verifies that the pages group matches only the paths of the pages contract.
     */
    @Test
    void pagesGroup_whenCalled_matchesOnlyThePages() {
        final var group = config.pagesGroup();

        assertEquals(OpenApiConfig.PAGES_GROUP, group.getGroup());
        assertEquals(List.of("/login", "/login/second-factor", "/login/second-factor/recovery-codes", "/oauth2/consent",
                "/logout"), group.getPathsToMatch());
        assertEquals("/v3/api-docs/pages", OpenApiConfig.PAGES_DOCS_PATH);
    }

    /**
     * Verifies that the pages group replaces the REST API's info block and bearer scheme with its own and the
     * session-cookie scheme.
     */
    @Test
    void pagesGroup_whenCustomizingTheDocument_describesThePagesAndTheSessionScheme() {
        final var document = config.authServerOpenApi();

        config.pagesGroup().getOpenApiCustomizers().forEach(customizer -> customizer.customise(document));

        assertEquals("Irurueta Auth Server Pages", document.getInfo().getTitle());
        final var schemes = document.getComponents().getSecuritySchemes();
        assertEquals(List.of(OpenApiConfig.SESSION_SCHEME), List.copyOf(schemes.keySet()));
        final var session = schemes.get(OpenApiConfig.SESSION_SCHEME);
        assertEquals(SecurityScheme.Type.APIKEY, session.getType());
        assertEquals(SecurityScheme.In.COOKIE, session.getIn());
        assertEquals("JSESSIONID", session.getName());
    }

    /**
     * Verifies that the pages group also describes a document that has no components yet.
     */
    @Test
    void pagesGroup_whenDocumentHasNoComponents_addsThem() {
        final var document = new OpenAPI();

        config.pagesGroup().getOpenApiCustomizers().forEach(customizer -> customizer.customise(document));

        assertEquals(List.of(OpenApiConfig.SESSION_SCHEME),
                List.copyOf(document.getComponents().getSecuritySchemes().keySet()));
    }
}
