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

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Integration tests of {@code GET /bff/user} through the whole filter chain.
 */
@SpringBootTest
@AutoConfigureMockMvc
class UserControllerIT {

    /** Subject of the signed-in user. */
    private static final String SUBJECT = "demo-user";

    /** Entry point to the web layer. */
    @Autowired
    private MockMvc mockMvc;

    /**
     * Verifies that an anonymous call gets a 401 instead of a redirect to the login page.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void user_whenCallerIsAnonymous_returnsUnauthorized() throws Exception {
        mockMvc.perform(get("/bff/user")).andExpect(status().isUnauthorized());
    }

    /**
     * Verifies that a signed-in user gets a JSON body holding its subject.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void user_whenCallerIsSignedIn_returnsItsSubject() throws Exception {
        mockMvc.perform(get("/bff/user")
                        .with(oidcLogin().idToken(token -> token.subject(SUBJECT))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.subject").value(SUBJECT));
    }
}
