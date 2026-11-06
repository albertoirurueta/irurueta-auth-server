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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.testsupport.PostgresIT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Integration test of the persistent session: signing in stores the session in PostgreSQL ({@code spring_session},
 * created by the Flyway migration) and hands the browser a hardened {@code __Host-} cookie.
 */
@PostgresIT
@AutoConfigureMockMvc
class BffSessionIT {

    /** Entry point to the web layer. */
    @Autowired
    private MockMvc mockMvc;

    /** Access to the session table. */
    @Autowired
    private JdbcTemplate jdbcTemplate;

    /**
     * Verifies that a signed-in request (the login endpoint creates the session) creates a row in
     * {@code spring_session} and sets the session cookie with the attributes the {@code __Host-} prefix requires.
     *
     * @throws Exception if the request cannot be performed.
     */
    @Test
    void session_whenUserSignsIn_isStoredInPostgresWithHardenedCookie() throws Exception {
        final var before = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM spring_session", Long.class);

        final var result = mockMvc.perform(get("/bff/login").with(oidcLogin()))
                .andExpect(status().isFound())
                .andReturn();

        final var cookieHeader = result.getResponse().getHeaders("Set-Cookie").stream()
                .filter(header -> header.startsWith("__Host-SESSION="))
                .findFirst().orElseThrow();
        assertTrue(cookieHeader.contains("; Secure"), cookieHeader);
        assertTrue(cookieHeader.contains("; HttpOnly"), cookieHeader);
        assertTrue(cookieHeader.contains("; SameSite=Lax"), cookieHeader);
        assertTrue(cookieHeader.contains("; Path=/"), cookieHeader);
        assertFalse(cookieHeader.contains("Domain"), cookieHeader);
        final var after = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM spring_session", Long.class);
        assertEquals(before + 1, after);
    }
}
