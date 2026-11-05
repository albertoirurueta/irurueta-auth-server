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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.api.web.password.PasswordConfiguration;
import com.irurueta.authserver.authorization.domain.password.CompromisedPasswordCheck;
import com.irurueta.authserver.testsupport.PostgresIT;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Checks, through the real login form and a PostgreSQL container, that a hash stored with an old algorithm is
 * replaced by the current Argon2 one the first time its owner signs in.
 */
@PostgresIT
@AutoConfigureMockMvc
class PasswordUpgradeIT {

    /** Prefix of an Argon2 hash in the delegating encoder's format. */
    private static final String ARGON2_PREFIX = "{" + PasswordConfiguration.DEFAULT_ENCODING_ID + "}";

    /** Prefix of a BCrypt hash in the delegating encoder's format. */
    private static final String BCRYPT_PREFIX = "{" + PasswordConfiguration.BCRYPT_ENCODING_ID + "}";

    /** Query that reads the stored hash of a user. */
    private static final String STORED_HASH = """
            SELECT p.encoded_password FROM user_passwords p JOIN users u ON u.id = p.user_id WHERE u.username = ?
            """;

    /** MockMvc bound to the application context. */
    @Autowired
    private MockMvc mockMvc;

    /** JDBC client that inserts the users and reads their hashes. */
    @Autowired
    private JdbcClient jdbcClient;

    /** Encoder of the application. */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /** The compromised-password check never reaches the network in tests. */
    @MockitoBean
    private CompromisedPasswordCheck compromisedPasswordCheck;

    /**
     * Verifies that a successful login replaces a BCrypt hash with an Argon2 one that still matches.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void login_whenStoredHashIsBcrypt_storesAnArgon2HashThatStillMatches() throws Exception {
        final var username = "user-" + UUID.randomUUID();
        final var credential = AuthServerFixtures.randomValue();
        insertUser(username, BCRYPT_PREFIX + new BCryptPasswordEncoder().encode(credential));
        assertTrue(storedHash(username).startsWith(BCRYPT_PREFIX));

        mockMvc.perform(post("/login").with(csrf()).param("username", username).param("password", credential))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/"));

        final var stored = storedHash(username);
        assertTrue(stored.startsWith(ARGON2_PREFIX), "the stored hash is upgraded");
        assertTrue(passwordEncoder.matches(credential, stored));
        assertFalse(passwordEncoder.upgradeEncoding(stored));
    }

    /**
     * Verifies that a failed login leaves the stored hash untouched.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void login_whenCredentialIsWrong_keepsTheStoredHash() throws Exception {
        final var username = "user-" + UUID.randomUUID();
        final var hash = BCRYPT_PREFIX + new BCryptPasswordEncoder().encode(AuthServerFixtures.randomValue());
        insertUser(username, hash);

        mockMvc.perform(post("/login").with(csrf()).param("username", username)
                        .param("password", AuthServerFixtures.randomValue()))
                .andExpect(redirectedUrl("/login?error"));

        assertEquals(hash, storedHash(username));
    }

    /**
     * Verifies that a hash that is already current is not rewritten.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void login_whenStoredHashIsCurrent_keepsTheStoredHash() throws Exception {
        final var username = "user-" + UUID.randomUUID();
        final var credential = AuthServerFixtures.randomValue();
        final var hash = passwordEncoder.encode(credential);
        insertUser(username, hash);

        mockMvc.perform(post("/login").with(csrf()).param("username", username).param("password", credential))
                .andExpect(redirectedUrl("/"));

        assertEquals(hash, storedHash(username));
    }

    /**
     * Inserts an enabled user with the given stored hash.
     *
     * @param username name of the user.
     * @param hash     stored hash, including its algorithm prefix.
     */
    private void insertUser(final String username, final String hash) {
        final var id = UUID.randomUUID();
        jdbcClient.sql("INSERT INTO users (id, username, enabled) VALUES (?, ?, true)").params(id, username).update();
        jdbcClient.sql("INSERT INTO user_passwords (user_id, encoded_password) VALUES (?, ?)").params(id, hash)
                .update();
        jdbcClient.sql("INSERT INTO user_authorities (user_id, authority) VALUES (?, 'ROLE_USER')").param(id).update();
    }

    /**
     * Reads the stored hash of a user.
     *
     * @param username name of the user.
     * @return the stored hash.
     */
    private String storedHash(final String username) {
        return jdbcClient.sql(STORED_HASH).param(username).query(String.class).single();
    }
}
