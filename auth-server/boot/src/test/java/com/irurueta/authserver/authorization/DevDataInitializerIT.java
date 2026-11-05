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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.infrastructure.persistence.dev.DevDataInitializer;
import com.irurueta.authserver.testsupport.PostgresIT;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;

/**
 * Checks the development data seeding against a PostgreSQL container, with the {@code dev} profile active.
 */
@PostgresIT
@ActiveProfiles("dev")
class DevDataInitializerIT {

    /** Initializer under test. */
    @Autowired
    private DevDataInitializer initializer;

    /** JDBC client used to count the seeded rows. */
    @Autowired
    private JdbcClient jdbcClient;

    /** Repository of registered clients. */
    @Autowired
    private RegisteredClientRepository clients;

    /** Service that loads the seeded user. */
    @Autowired
    private UserDetailsService userDetailsService;

    /** Encoder of the application. */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /**
     * Verifies that the data is created once, even if the initializer runs again.
     */
    @Test
    void run_whenCalledRepeatedly_createsDataOnceAndIsIdempotent() {
        // the runner already executed once at context start; running it again must not duplicate anything
        initializer.run(new DefaultApplicationArguments());
        initializer.run(new DefaultApplicationArguments());

        assertEquals(1, jdbcClient.sql("SELECT count(*) FROM users WHERE username = 'demo'")
                .query(Integer.class).single());
        assertEquals(1, jdbcClient.sql("SELECT count(*) FROM oauth2_registered_client WHERE client_id = 'bff'")
                .query(Integer.class).single());

        final var user = userDetailsService.loadUserByUsername("demo");
        assertEquals(List.of("ROLE_USER"), user.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList());
        assertTrue(user.getPassword().startsWith("{bcrypt}"));

        final var client = clients.findByClientId("bff");
        assertNotNull(client);
        assertTrue(client.getClientSettings().isRequireProofKey());
        assertFalse(passwordEncoder.upgradeEncoding(client.getClientSecret()));
    }
}
