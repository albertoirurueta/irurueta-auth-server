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
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.oidcLogin;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.testsupport.PostgresIT;
import java.time.Duration;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.session.jdbc.autoconfigure.JdbcSessionDataSourceScriptDatabaseInitializer;
import org.springframework.boot.session.jdbc.autoconfigure.JdbcSessionProperties;
import org.springframework.boot.sql.init.DatabaseInitializationMode;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.session.SessionRepository;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Integration test of the persistent session: signing in stores the session in PostgreSQL ({@code spring_session},
 * created by the Flyway migration) and hands the browser a hardened {@code __Host-} cookie, and Spring Boot's session
 * auto-configuration, with its {@code spring.session.*} properties, is in effect. The session timeout is set to an
 * unusual value so that only the auto-configuration can have applied it.
 */
@PostgresIT
@AutoConfigureMockMvc
@TestPropertySource(properties = "spring.session.timeout=" + BffSessionIT.SESSION_TIMEOUT_MINUTES + "m")
class BffSessionIT {

    /** Session timeout, in minutes, set through {@code spring.session.timeout}. */
    static final long SESSION_TIMEOUT_MINUTES = 17;

    /** Properties of the Spring Session JDBC auto-configuration; absent when it has backed off. */
    @Autowired
    private ObjectProvider<JdbcSessionProperties> jdbcSessionProperties;

    /** Initializer of the Spring Session schema; only created when the schema is not left to Flyway. */
    @Autowired
    private ObjectProvider<JdbcSessionDataSourceScriptDatabaseInitializer> schemaInitializer;

    /** The session repository (Spring Session JDBC's, seen through its interface: its session type is not public). */
    @Autowired
    private SessionRepository<?> sessionRepository;

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

    /**
     * Verifies that Spring Boot's session auto-configuration is active and honours
     * {@code spring.session.jdbc.initialize-schema: never}: its properties are bound and no schema initializer exists,
     * so the schema stays owned by Flyway.
     */
    @Test
    void sessionAutoConfiguration_whenInitializeSchemaIsNever_bindsPropertiesAndCreatesNoInitializer() {
        final var properties = jdbcSessionProperties.getIfAvailable();

        assertEquals(DatabaseInitializationMode.NEVER, properties.getInitializeSchema());
        assertNull(schemaInitializer.getIfAvailable());
    }

    /**
     * Verifies that the {@code spring.session.timeout} property reaches the session repository, which it would not if
     * the auto-configuration were switched off.
     */
    @Test
    void sessionRepository_whenSessionTimeoutIsConfigured_createsSessionsWithThatTimeout() {
        assertEquals(Duration.ofMinutes(SESSION_TIMEOUT_MINUTES),
                sessionRepository.createSession().getMaxInactiveInterval());
    }
}
