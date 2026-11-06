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
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.password.CompromisedPasswordCheck;
import com.irurueta.authserver.testsupport.PostgresIT;
import java.util.Locale;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Checks, through the real login form, the real authentication provider of
 * {@code PasswordAuthenticationConfiguration} and a PostgreSQL container, that the login page never reveals that an
 * account exists: a wrong password for a disabled account gets exactly the page an unknown user gets, and only the
 * correct password reveals that the account is disabled.
 */
@PostgresIT
@AutoConfigureMockMvc
class PasswordAuthenticationIT {

    /** Path of the login page. */
    private static final String LOGIN = "/login";

    /** Text of the generic error message. */
    private static final String GENERIC_MESSAGE = "Invalid username or password.";

    /** Text of the message of a disabled account. */
    private static final String DISABLED_MESSAGE = "This account is disabled.";

    /** MockMvc bound to the application context. */
    @Autowired
    private MockMvc mockMvc;

    /** JDBC client that inserts the users. */
    @Autowired
    private JdbcClient jdbcClient;

    /** Encoder of the application. */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /** The compromised-password check never reaches the network in tests. */
    @MockitoBean
    private CompromisedPasswordCheck compromisedPasswordCheck;

    /**
     * Pins the locale of the localized text the assertions read.
     */
    @BeforeEach
    void setUp() {
        LocaleContextHolder.setLocale(Locale.ENGLISH);
    }

    /**
     * Verifies that a wrong password for a disabled account shows the same page as an unknown user, with the generic
     * message and without the disabled one.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void formLogin_whenDisabledAccountGetsWrongPassword_showsTheSamePageAsAnUnknownUser() throws Exception {
        final var username = "disabled-" + UUID.randomUUID();
        insertDisabledUser(username, AuthServerFixtures.randomValue());

        final var disabled = errorPage(failedLogin(username, AuthServerFixtures.randomValue()));
        final var unknown = errorPage(failedLogin("unknown-" + UUID.randomUUID(), AuthServerFixtures.randomValue()));

        assertTrue(disabled.contains(GENERIC_MESSAGE), disabled);
        assertFalse(disabled.contains(DISABLED_MESSAGE), disabled);
        // the CSRF token differs between sessions, so compare the pages without it
        assertEquals(stripToken(unknown), stripToken(disabled));
    }

    /**
     * Verifies that the correct password for a disabled account shows the disabled message.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void formLogin_whenDisabledAccountGetsCorrectPassword_showsTheDisabledMessage() throws Exception {
        final var username = "disabled-" + UUID.randomUUID();
        final var credential = AuthServerFixtures.randomValue();
        insertDisabledUser(username, credential);

        final var page = errorPage(failedLogin(username, credential));

        assertTrue(page.contains(DISABLED_MESSAGE), page);
        assertFalse(page.contains(GENERIC_MESSAGE), page);
    }

    /**
     * Posts the login form, expects it to fail and returns the session that holds the failure.
     *
     * @param username username to post.
     * @param password password to post.
     * @return the session of the failed attempt.
     * @throws Exception if the request cannot be performed.
     */
    private MockHttpSession failedLogin(final String username, final String password) throws Exception {
        return (MockHttpSession) mockMvc.perform(post(LOGIN).with(csrf())
                        .param("username", username).param("password", password))
                .andExpect(redirectedUrl(LOGIN + "?error"))
                .andReturn().getRequest().getSession();
    }

    /**
     * Renders the login page that follows a failed sign-in.
     *
     * @param session the session of the failed attempt.
     * @return the page.
     * @throws Exception if the request cannot be performed.
     */
    private String errorPage(final MockHttpSession session) throws Exception {
        return mockMvc.perform(get(LOGIN).queryParam("error", "").session(session).locale(Locale.ENGLISH))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();
    }

    /**
     * Inserts a disabled user with one role.
     *
     * @param username   name of the user.
     * @param credential clear-text password of the user, generated by the test.
     */
    private void insertDisabledUser(final String username, final String credential) {
        final var id = UUID.randomUUID();
        jdbcClient.sql("INSERT INTO users (id, username, enabled) VALUES (?, ?, false)").params(id, username).update();
        jdbcClient.sql("INSERT INTO user_passwords (user_id, encoded_password) VALUES (?, ?)")
                .params(id, passwordEncoder.encode(credential)).update();
        jdbcClient.sql("INSERT INTO user_authorities (user_id, authority) VALUES (?, 'ROLE_USER')").param(id).update();
    }

    /**
     * Removes the CSRF token value from a page.
     *
     * @param html the page.
     * @return the page without the token value.
     */
    private static String stripToken(final String html) {
        return html.replaceAll("name=\"_csrf\" value=\"[^\"]*\"", "name=\"_csrf\"");
    }
}
