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

package com.irurueta.authserver.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.testsupport.PostgresIT;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.SerializationFeature;
import tools.jackson.databind.json.JsonMapper;

/**
 * Fails when the published OpenAPI document differs from the committed {@code openapi/auth-server.json}, so API
 * changes are always reviewed. Run with {@code -Dopenapi.update=true} to rewrite the committed file.
 */
@PostgresIT
@AutoConfigureMockMvc
class OpenApiDriftIT {

    private static final String UPDATE_PROPERTY = "openapi.update";

    private static final Path COMMITTED = Path.of("..", "openapi", "auth-server.json");

    @Autowired
    private MockMvc mockMvc;

    @Test
    void apiDocs_matchCommittedOpenApiFile() throws Exception {
        final var body = mockMvc.perform(get(OpenApiConfig.API_DOCS_PATH))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);
        final var actual = normalize(body);

        if (Boolean.getBoolean(UPDATE_PROPERTY)) {
            Files.createDirectories(COMMITTED.getParent());
            Files.writeString(COMMITTED, actual, StandardCharsets.UTF_8);
            return;
        }

        assertThat(COMMITTED)
                .as("committed OpenAPI file; regenerate it with: ./mvnw -pl auth-server verify -D%s=true "
                        + "-Dit.test=OpenApiDriftIT", UPDATE_PROPERTY)
                .exists();
        assertThat(actual)
                .as("The published API differs from %s. If the change is intended, regenerate the file with: "
                        + "./mvnw -pl auth-server verify -D%s=true -Dit.test=OpenApiDriftIT and commit it.",
                        COMMITTED, UPDATE_PROPERTY)
                .isEqualTo(Files.readString(COMMITTED, StandardCharsets.UTF_8));
    }

    /** Pretty-prints the document with sorted keys and without the server list, which depends on the test port. */
    private static String normalize(final String json) {
        final var mapper = JsonMapper.builder()
                .enable(SerializationFeature.INDENT_OUTPUT)
                .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
                .build();
        @SuppressWarnings("unchecked")
        final var document = (java.util.Map<String, Object>) mapper.readValue(json, java.util.Map.class);
        document.remove("servers");
        return mapper.writeValueAsString(document) + System.lineSeparator();
    }
}
