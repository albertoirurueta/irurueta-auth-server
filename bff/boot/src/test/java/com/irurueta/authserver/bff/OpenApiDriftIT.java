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

package com.irurueta.authserver.bff;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.bff.api.web.OpenApiConfig;
import com.irurueta.authserver.testsupport.OpenApiContract;
import com.irurueta.authserver.testsupport.PostgresIT;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Fails when the JSON API the running BFF serves drifts from its contract {@code apis/bff/rest-server/bff-api-v1.yaml}:
 * an endpoint mapped by hand outside the generated interface, a contract operation no controller implements, or a
 * different status code, parameter, body, security requirement or schema. The OpenAPI document springdoc serves (to a
 * signed-in user, like every BFF page) is built from the running application's mappings and the annotations
 * generated from the contract, and both are compared through {@link OpenApiContract}.
 */
@PostgresIT
@AutoConfigureMockMvc
class OpenApiDriftIT {

    /** The contract, relative to the directory of this module. */
    private static final Path CONTRACT = Path.of("..", "..", "apis", "bff", "rest-server", "bff-api-v1.yaml");

    /** Prefix of the paths of the JSON API. */
    private static final String API_PREFIX = "/bff/";

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
        final var body = mockMvc.perform(get(OpenApiConfig.API_DOCS_PATH).with(oidcLogin()))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString(StandardCharsets.UTF_8);

        final var expected = OpenApiContract.summarize(OpenApiContract.read(CONTRACT), API_PREFIX);
        final var actual = OpenApiContract.summarize(OpenApiContract.parse(body), API_PREFIX);

        assertEquals(expected, OpenApiContract.restrictTo(actual, expected),
                "The served API differs from " + CONTRACT + ". Change the contract (the interface and DTOs are "
                        + "generated from it) instead of mapping an endpoint by hand.");
    }
}
