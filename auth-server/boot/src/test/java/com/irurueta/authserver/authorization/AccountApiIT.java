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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.account.AccountMailer;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.password.CompromisedPasswordCheck;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.testsupport.PostgresIT;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import tools.jackson.databind.json.JsonMapper;

/**
 * Checks the account API against the real application: registration with e-mail verification, password change,
 * password reset with a single-use token, and the identical answers that keep unknown accounts undisclosed. The
 * mailer is mocked so the tests can read the tokens it would send; the compromised-password check is mocked so no
 * request leaves the machine.
 */
@PostgresIT(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class AccountApiIT {

    /** Path of the registration endpoint. */
    private static final String REGISTER_PATH = "/api/account/register";

    /** Path of the password change endpoint. */
    private static final String CHANGE_PATH = "/api/account/password";

    /** Path of the endpoint that requests a reset link. */
    private static final String RESET_REQUEST_PATH = "/api/account/password/reset-request";

    /** Path of the endpoint that resets a password. */
    private static final String RESET_PATH = "/api/account/password/reset";

    /** Writes the request bodies. */
    private static final JsonMapper JSON = JsonMapper.builder().build();

    /** MockMvc bound to the application context. */
    @Autowired
    private MockMvc mockMvc;

    /** JDBC client that reads the stored state. */
    @Autowired
    private JdbcClient jdbcClient;

    /** Encoder of the application. */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /** Port that stores user accounts. */
    @Autowired
    private UserAccountRepository userAccounts;

    /** Port that stores client registrations. */
    @Autowired
    private ClientRegistrationRepository clientRegistrations;

    /** Mailer whose messages the tests read. */
    @MockitoBean
    private AccountMailer accountMailer;

    /** The compromised-password check never reaches the network in tests. */
    @MockitoBean
    private CompromisedPasswordCheck compromisedPasswordCheck;

    /** Fixtures of the test. */
    private AuthServerFixtures fixtures;

    /** Creates the fixtures. */
    @BeforeEach
    void setUp() {
        fixtures = new AuthServerFixtures(mockMvc, passwordEncoder, userAccounts, clientRegistrations);
    }

    /**
     * Verifies that a registered account is disabled until its e-mail token is used, and that the token verifies
     * the address, enables the account and can be used to sign in.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void register_whenNewAccount_isEnabledOnlyAfterTheEmailIsVerified() throws Exception {
        final var username = "user-" + UUID.randomUUID();
        final var email = username + "@example.com";
        final var credential = AuthServerFixtures.randomValue();

        register(username, email, credential).andExpect(status().isAccepted());

        assertFalse(isEnabled(username));
        final var token = ArgumentCaptor.<String>captor();
        verify(accountMailer).sendEmailVerification(eq(email), token.capture());
        mockMvc.perform(post("/login").with(csrf()).param("username", username).param("password", credential))
                .andExpect(redirectedUrl("/login?error"));

        mockMvc.perform(get("/api/account/verify").param("token", token.getValue()))
                .andExpect(status().isNoContent());

        assertTrue(isEnabled(username));
        assertTrue(jdbcClient.sql("SELECT email_verified FROM users WHERE username = ?").param(username)
                .query(Boolean.class).single());
        mockMvc.perform(post("/login").with(csrf()).param("username", username).param("password", credential))
                .andExpect(redirectedUrl("/"));
    }

    /**
     * Verifies that a token that is not a verification token is rejected.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void verify_whenTokenIsInvalid_returnsBadRequest() throws Exception {
        mockMvc.perform(get("/api/account/verify").param("token", AuthServerFixtures.randomValue()))
                .andExpect(status().isBadRequest());
    }

    /**
     * Verifies that registering a taken e-mail address answers like a new one, creates nothing and tells the
     * owner by e-mail.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void register_whenEmailIsTaken_answersTheSameAndMailsTheOwner() throws Exception {
        final var email = "owner-" + UUID.randomUUID() + "@example.com";
        register("user-" + UUID.randomUUID(), email, AuthServerFixtures.randomValue())
                .andExpect(status().isAccepted());

        register("user-" + UUID.randomUUID(), email, AuthServerFixtures.randomValue())
                .andExpect(status().isAccepted());

        verify(accountMailer).sendAlreadyRegistered(email);
        assertEquals(1, jdbcClient.sql("SELECT count(*) FROM users WHERE lower(email) = ?").param(email)
                .query(Integer.class).single());
    }

    /**
     * Verifies that a compromised password is rejected at registration.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void register_whenPasswordIsCompromised_returnsBadRequest() throws Exception {
        final var credential = AuthServerFixtures.randomValue();
        when(compromisedPasswordCheck.isCompromised(credential)).thenReturn(true);

        register("user-" + UUID.randomUUID(), "x-" + UUID.randomUUID() + "@example.com", credential)
                .andExpect(status().isBadRequest());
    }

    /**
     * Verifies that changing the password updates the hash and revokes every authorization of the user.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void changePassword_whenCurrentPasswordIsRight_updatesTheHashAndRevokesAuthorizations() throws Exception {
        final var user = fixtures.createUser();
        final var tokens = fixtures.authorizationCodeTokens(user, fixtures.createCodeClient());
        assertEquals(1, authorizationCount(user.username()));
        final var replacement = AuthServerFixtures.randomValue();

        mockMvc.perform(post(CHANGE_PATH)
                        .header("Authorization", "Bearer " + tokens.get("access_token").asString())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(
                                Map.of("currentPassword", user.credential(), "newPassword", replacement))))
                .andExpect(status().isNoContent());

        assertEquals(0, authorizationCount(user.username()));
        assertTrue(passwordEncoder.matches(replacement, storedHash(user.username())));
    }

    /**
     * Verifies that a wrong current password changes nothing.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void changePassword_whenCurrentPasswordIsWrong_returnsBadRequestAndKeepsAuthorizations() throws Exception {
        final var user = fixtures.createUser();
        final var tokens = fixtures.authorizationCodeTokens(user, fixtures.createCodeClient());
        final var before = storedHash(user.username());

        mockMvc.perform(post(CHANGE_PATH)
                        .header("Authorization", "Bearer " + tokens.get("access_token").asString())
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("currentPassword", AuthServerFixtures.randomValue(),
                                "newPassword", AuthServerFixtures.randomValue()))))
                .andExpect(status().isBadRequest());

        assertEquals(before, storedHash(user.username()));
        assertEquals(1, authorizationCount(user.username()));
    }

    /**
     * Verifies that changing the password needs a bearer token.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void changePassword_whenThereIsNoToken_returnsUnauthorized() throws Exception {
        mockMvc.perform(post(CHANGE_PATH).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"currentPassword\":\"a\",\"newPassword\":\"b\"}"))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Verifies that a reset token works once, replaces the password, revokes the authorizations and fails the
     * second time.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void resetPassword_whenTokenIsUsedTwice_succeedsOnlyTheFirstTime() throws Exception {
        final var user = fixtures.createUser();
        fixtures.authorizationCodeTokens(user, fixtures.createCodeClient());
        mockMvc.perform(post(RESET_REQUEST_PATH).contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("email", user.email()))))
                .andExpect(status().isAccepted());
        final var token = ArgumentCaptor.<String>captor();
        verify(accountMailer).sendPasswordReset(eq(user.email()), token.capture());
        final var replacement = AuthServerFixtures.randomValue();

        reset(token.getValue(), replacement).andExpect(status().isNoContent());

        assertTrue(passwordEncoder.matches(replacement, storedHash(user.username())));
        assertEquals(0, authorizationCount(user.username()));
        reset(token.getValue(), AuthServerFixtures.randomValue()).andExpect(status().isBadRequest());
        assertTrue(passwordEncoder.matches(replacement, storedHash(user.username())));
    }

    /**
     * Verifies that an unknown reset token is rejected.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void resetPassword_whenTokenIsUnknown_returnsBadRequest() throws Exception {
        reset(AuthServerFixtures.randomValue(), AuthServerFixtures.randomValue()).andExpect(status().isBadRequest());
    }

    /**
     * Verifies that asking for a reset link of an unknown address is answered exactly like a known one, and sends
     * the owner no link.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void requestPasswordReset_whenAddressIsUnknown_answersLikeAKnownOne() throws Exception {
        final var known = fixtures.createUser();
        final var unknown = "nobody-" + UUID.randomUUID() + "@example.com";

        final var knownAnswer = mockMvc.perform(post(RESET_REQUEST_PATH).contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("email", known.email()))))
                .andReturn().getResponse();
        final var unknownAnswer = mockMvc.perform(post(RESET_REQUEST_PATH).contentType(MediaType.APPLICATION_JSON)
                        .content(JSON.writeValueAsString(Map.of("email", unknown))))
                .andReturn().getResponse();

        assertEquals(knownAnswer.getStatus(), unknownAnswer.getStatus());
        assertEquals(HttpStatus.ACCEPTED.value(), unknownAnswer.getStatus());
        assertEquals(knownAnswer.getContentAsString(), unknownAnswer.getContentAsString());
        verify(accountMailer).sendNoAccountFound(unknown);
        verify(accountMailer, never()).sendPasswordReset(eq(unknown), anyString());
    }

    /**
     * Posts a registration.
     *
     * @param username   desired username.
     * @param email      e-mail address.
     * @param credential chosen password.
     * @return the result of the request.
     * @throws Exception if the request cannot be performed.
     */
    private ResultActions register(final String username, final String email, final String credential)
            throws Exception {
        return mockMvc.perform(post(REGISTER_PATH).contentType(MediaType.APPLICATION_JSON)
                .content(JSON.writeValueAsString(
                        Map.of("username", username, "email", email, "password", credential))));
    }

    /**
     * Posts a password reset.
     *
     * @param token       reset token.
     * @param replacement password to set.
     * @return the result of the request.
     * @throws Exception if the request cannot be performed.
     */
    private ResultActions reset(final String token, final String replacement) throws Exception {
        return mockMvc.perform(post(RESET_PATH).contentType(MediaType.APPLICATION_JSON)
                .content(JSON.writeValueAsString(Map.of("token", token, "newPassword", replacement))));
    }

    /**
     * Tells whether a user is enabled.
     *
     * @param username name of the user.
     * @return whether the user is enabled.
     */
    private boolean isEnabled(final String username) {
        return jdbcClient.sql("SELECT enabled FROM users WHERE username = ?").param(username)
                .query(Boolean.class).single();
    }

    /**
     * Counts the OAuth 2 authorizations of a user.
     *
     * @param username name of the user.
     * @return the number of authorizations.
     */
    private int authorizationCount(final String username) {
        return jdbcClient.sql("SELECT count(*) FROM oauth2_authorization WHERE principal_name = ?").param(username)
                .query(Integer.class).single();
    }

    /**
     * Reads the stored hash of a user.
     *
     * @param username name of the user.
     * @return the stored hash.
     */
    private String storedHash(final String username) {
        return jdbcClient.sql("""
                SELECT p.encoded_password FROM user_passwords p JOIN users u ON u.id = p.user_id
                WHERE u.username = ?
                """).param(username).query(String.class).single();
    }
}
