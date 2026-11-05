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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.testsupport.PostgresIT;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Starts the application next to a Testcontainers PostgreSQL instance and checks its public health endpoint.
 */
@PostgresIT
@AutoConfigureMockMvc
class ResourceServerApplicationIT {

    /** Entry point to the web layer. */
    @Autowired
    private MockMvc mockMvc;

    /** Resource server properties read from the configuration. */
    @Autowired
    private OAuth2ResourceServerProperties resourceServerProperties;

    /**
     * Fails if the application context cannot start.
     */
    @Test
    void contextLoads_whenApplicationStarts_succeeds() {
        // the context is started by the test framework; reaching this point is the assertion
    }

    /**
     * Verifies that accepted tokens are restricted to the resource server's own audience.
     */
    @Test
    void jwtAudiences_whenDefaultsApply_areRestrictedToTheResourceServerAudience() {
        assertEquals(List.of("resource-server"), resourceServerProperties.getJwt().getAudiences());
    }

    /**
     * Verifies that the health endpoint is public and reports the application as up.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void actuatorHealth_whenCalledAnonymously_isUp() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("UP"));
    }
}
