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

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.testsupport.PostgresIT;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Checks signing out of the running application: the local logout invalidates the session, and the OpenID Connect
 * RP-initiated logout (which the default OIDC configuration already exposes) honours a
 * {@code post_logout_redirect_uri} only when the client has registered it.
 */
@PostgresIT
@AutoConfigureMockMvc
class LogoutIT {

    /** Post-logout redirect URI the test client registers. */
    private static final String REGISTERED_URI = "http://127.0.0.1:8080/signed-out";

    /** URI the client has not registered. */
    private static final String UNREGISTERED_URI = "http://evil.example.test/signed-out";

    /** Path of the OpenID Connect RP-initiated logout endpoint. */
    private static final String CONNECT_LOGOUT = "/connect/logout";

    /** Name of the logout parameter that carries the ID token. */
    private static final String ID_TOKEN_HINT = "id_token_hint";

    /** Name of the logout parameter that carries the post-logout redirect URI. */
    private static final String POST_LOGOUT_REDIRECT_URI = "post_logout_redirect_uri";

    /** MockMvc bound to the application context. */
    @Autowired
    private MockMvc mockMvc;

    /** Encoder of the application. */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /** Port that stores the users. */
    @Autowired
    private UserAccountRepository userAccounts;

    /** Port that stores the client registrations. */
    @Autowired
    private ClientRegistrationRepository clientRegistrations;

    /** Browser session of the signed-in user. */
    private MockHttpSession session;

    /** ID token the client received when the user signed in. */
    private String idToken;

    /**
     * Signs a user in through a client that registered one post-logout redirect URI.
     *
     * @throws Exception if a request cannot be performed.
     */
    @BeforeEach
    void signIn() throws Exception {
        final var fixtures = new AuthServerFixtures(mockMvc, passwordEncoder, userAccounts, clientRegistrations);
        final var client = fixtures.createCodeClient(List.of(REGISTERED_URI));
        session = new MockHttpSession();
        idToken = fixtures.authorizationCodeTokens(fixtures.createUser(), client, session)
                .get("id_token").asString();
    }

    /**
     * Verifies that the confirmation page is shown to a signed-in user and posts to the logout endpoint with the CSRF
     * token.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void logoutPage_whenUserIsSignedIn_asksForConfirmation() throws Exception {
        mockMvc.perform(get("/logout").session(session))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Do you want to sign out?")))
                .andExpect(content().string(containsString("action=\"/logout\"")))
                .andExpect(content().string(containsString("name=\"_csrf\"")));
    }

    // tag::logout-it[]
    /**
     * Verifies that posting to the logout endpoint invalidates the session and returns to the login page.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void logout_whenUserConfirms_invalidatesTheSession() throws Exception {
        mockMvc.perform(post("/logout").session(session).with(csrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/login?logout"));

        assertTrue(session.isInvalid());
    }
    // end::logout-it[]

    /**
     * Verifies that a logout without the CSRF token is refused and keeps the session.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void logout_whenCsrfTokenIsMissing_isForbiddenAndKeepsTheSession() throws Exception {
        mockMvc.perform(post("/logout").session(session)).andExpect(status().isForbidden());

        assertFalse(session.isInvalid());
    }

    /**
     * Verifies that the RP-initiated logout sends the user to the registered post-logout redirect URI and ends the
     * session.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void connectLogout_whenRedirectUriIsRegistered_redirectsToItAndInvalidatesTheSession() throws Exception {
        mockMvc.perform(get(CONNECT_LOGOUT).session(session)
                        .queryParam(ID_TOKEN_HINT, idToken).queryParam(POST_LOGOUT_REDIRECT_URI, REGISTERED_URI)
                        .queryParam("state", "s"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl(REGISTERED_URI + "?state=s"));

        assertTrue(session.isInvalid());
    }

    /**
     * Verifies that a post-logout redirect URI the client has not registered is never honoured: the request is
     * refused and the session is kept.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void connectLogout_whenRedirectUriIsNotRegistered_isRejectedWithoutRedirecting() throws Exception {
        mockMvc.perform(get(CONNECT_LOGOUT).session(session)
                        .queryParam(ID_TOKEN_HINT, idToken).queryParam(POST_LOGOUT_REDIRECT_URI, UNREGISTERED_URI))
                .andExpect(status().is4xxClientError())
                .andExpect(header().string("Location", not(containsString(UNREGISTERED_URI))));

        assertFalse(session.isInvalid());
    }
}
