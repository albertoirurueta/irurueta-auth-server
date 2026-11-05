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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.resourceserver.api.web.OpenApiConfig;
import com.irurueta.authserver.testsupport.OpenApiContract;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Fails when the API the running application serves drifts from its contract
 * {@code apis/resource-server/rest-server/resource-server-api-v1.yaml}: an endpoint mapped by hand outside the
 * generated interface, a contract operation no controller implements, or a different status code, parameter, body,
 * security requirement or schema. The OpenAPI document springdoc serves is built from the running application's
 * mappings and the annotations generated from the contract, and both are compared through {@link OpenApiContract}.
 * Only {@code /api/**} is compared, so the test-only endpoints of this module's integration tests are left out.
 */
@SpringBootTest
@AutoConfigureMockMvc
class OpenApiDriftIT {

    /** The contract, relative to the directory of this module. */
    private static final Path CONTRACT = Path.of("..", "..", "apis", "resource-server", "rest-server",
            "resource-server-api-v1.yaml");

    /** Prefix of the paths of the REST API. */
    private static final String API_PREFIX = "/api/";

    /** MockMvc bound to the application context. */
    @Autowired
    private MockMvc mockMvc;

    /**
     * Verifies that the served OpenAPI document describes exactly the API of the contract.
     *
     * @throws Exception if the document cannot be fetched or the contract cannot be read.
     */
    @Test
    void apiDocs_whenApplicationRuns_matchContract() throws Exception {
        final var body = mockMvc.perform(get(OpenApiConfig.API_DOCS_PATH))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        final var expected = OpenApiContract.summarize(OpenApiContract.read(CONTRACT), API_PREFIX);
        final var actual = OpenApiContract.summarize(OpenApiContract.parse(body), API_PREFIX);

        assertEquals(expected, OpenApiContract.restrictTo(actual, expected),
                "The served API differs from " + CONTRACT + ". Change the contract (the interface and DTOs are "
                        + "generated from it) instead of mapping an endpoint by hand.");
    }
}
