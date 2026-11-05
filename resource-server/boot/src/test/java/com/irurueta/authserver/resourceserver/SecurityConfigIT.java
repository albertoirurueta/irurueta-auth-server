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

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Integration tests of {@link com.irurueta.authserver.resourceserver.api.web.security.SecurityConfig} through the
 * whole filter chain, against the test-only {@link ProtectedTestController}.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityConfigIT {

    /** Subject of the test bearer token. */
    private static final String SUBJECT = "demo";

    /** Entry point to the web layer. */
    @Autowired
    private MockMvc mockMvc;

    /**
     * Verifies that a request without a bearer token is rejected.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void resourceServerFilterChain_whenThereIsNoToken_returnsUnauthorized() throws Exception {
        mockMvc.perform(get(ProtectedTestController.PATH)).andExpect(status().isUnauthorized());
    }

    /**
     * Verifies that a request with a valid JWT reaches the endpoint with the token's claims.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void resourceServerFilterChain_whenTokenIsValid_exposesTheTokenToTheEndpoint() throws Exception {
        mockMvc.perform(get(ProtectedTestController.PATH).with(jwt().jwt(token -> token.subject(SUBJECT))))
                .andExpect(status().isOk())
                .andExpect(content().string(SUBJECT));
    }
}
