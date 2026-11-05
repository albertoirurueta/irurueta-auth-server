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
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Integration tests of {@code GET /orders} through the whole filter chain.
 */
@SpringBootTest
@AutoConfigureMockMvc
class OrdersControllerIT {

    /** Number of demo orders. */
    private static final int ORDER_COUNT = 2;

    /** Price of the first demo order. */
    private static final double FIRST_ORDER_TOTAL = 49.90;

    /** Entry point to the web layer. */
    @Autowired
    private MockMvc mockMvc;

    /**
     * Verifies that a request without a bearer token is rejected.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void orders_whenThereIsNoToken_returnsUnauthorized() throws Exception {
        mockMvc.perform(get("/orders")).andExpect(status().isUnauthorized());
    }

    /**
     * Verifies that a request with a valid JWT lists the demo orders.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void orders_whenTokenIsValid_returnsTheDemoOrders() throws Exception {
        mockMvc.perform(get("/orders").with(jwt()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(ORDER_COUNT))
                .andExpect(jsonPath("$[0].id").value("1001"))
                .andExpect(jsonPath("$[0].item").value("Keyboard"))
                .andExpect(jsonPath("$[0].total").value(FIRST_ORDER_TOTAL))
                .andExpect(jsonPath("$[1].id").value("1002"));
    }
}
