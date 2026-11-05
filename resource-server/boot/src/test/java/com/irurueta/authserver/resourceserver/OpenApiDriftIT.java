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

package com.irurueta.authserver.resourceserver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.resourceserver.api.web.OpenApiConfig;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.core.type.TypeReference;
import tools.jackson.core.util.DefaultIndenter;
import tools.jackson.core.util.DefaultPrettyPrinter;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * Fails when the published OpenAPI document differs from the committed {@code openapi/resource-server.json}, so API
 * changes are always reviewed. Run with {@code -Dopenapi.update=true} to rewrite the committed file. The document
 * is always written and compared with {@code \n} line endings, so the result does not depend on the platform.
 */
@SpringBootTest
@AutoConfigureMockMvc
class OpenApiDriftIT {

    /** Name of the system property that rewrites the committed file instead of comparing with it. */
    private static final String UPDATE_PROPERTY = "openapi.update";

    /** Line ending of the committed file, never the platform's own. */
    private static final String LINE_FEED = "\n";

    /** Indentation of the committed file. */
    private static final String INDENT = "  ";

    /** Committed OpenAPI file, relative to the directory of this module. */
    private static final Path COMMITTED = Path.of("..", "..", "openapi", "resource-server.json");

    /** MockMvc bound to the application context. */
    @Autowired
    private MockMvc mockMvc;

    /**
     * Verifies that the published OpenAPI document equals the committed one.
     *
     * @throws Exception if the document cannot be read or written.
     */
    @Test
    void apiDocs_whenApiIsUnchanged_matchCommittedOpenApiFile() throws Exception {
        final var body = mockMvc.perform(get(OpenApiConfig.API_DOCS_PATH))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        final var actual = normalize(body);

        if (Boolean.getBoolean(UPDATE_PROPERTY)) {
            Files.createDirectories(COMMITTED.getParent());
            Files.writeString(COMMITTED, actual, StandardCharsets.UTF_8);
            return;
        }

        assertTrue(Files.exists(COMMITTED), "committed OpenAPI file missing; regenerate it with: "
                + "./mvnw -pl resource-server/boot -am verify -D" + UPDATE_PROPERTY + "=true -Dit.test=OpenApiDriftIT");
        assertEquals(Files.readString(COMMITTED, StandardCharsets.UTF_8), actual,
                "The published API differs from " + COMMITTED + ". If the change is intended, regenerate the file "
                        + "with: ./mvnw -pl resource-server/boot -am verify -D" + UPDATE_PROPERTY
                        + "=true -Dit.test=OpenApiDriftIT and commit it.");
    }

    /**
     * Pretty-prints the document with sorted keys, {@code \n} line endings and without the server list, which
     * depends on the test port.
     *
     * @param json document as published.
     * @return the normalized document.
     */
    private static String normalize(final String json) {
        final var mapper = JsonMapper.builder()
                .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
                .build();
        final var printer = new DefaultPrettyPrinter()
                .withObjectIndenter(new DefaultIndenter(INDENT, LINE_FEED))
                .withArrayIndenter(new DefaultIndenter(INDENT, LINE_FEED));
        final Map<String, Object> document = mapper.readValue(json, new TypeReference<>() { });
        document.remove("servers");
        return mapper.writer().with(printer).writeValueAsString(document) + LINE_FEED;
    }
}
