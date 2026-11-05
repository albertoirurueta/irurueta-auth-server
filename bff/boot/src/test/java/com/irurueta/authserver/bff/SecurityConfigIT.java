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

import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Integration tests of the BFF security filter chain.
 */
@SpringBootTest
@AutoConfigureMockMvc
class SecurityConfigIT {

    /** Entry point to the web layer. */
    @Autowired
    private MockMvc mockMvc;

    /**
     * Verifies that the authorization request uses PKCE and asks for the OpenID scopes.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void bffFilterChain_whenAuthorizationIsRequested_usesPkce() throws Exception {
        mockMvc.perform(get("/oauth2/authorization/bff"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", containsString("code_challenge=")))
                .andExpect(header().string("Location", containsString("code_challenge_method=S256")))
                .andExpect(header().string("Location", containsString("scope=openid%20profile")));
    }

    /**
     * Verifies that the health endpoint needs no authentication.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void bffFilterChain_whenHealthIsRequested_isPublic() throws Exception {
        mockMvc.perform(get("/actuator/health")).andExpect(status().isOk());
    }
}
