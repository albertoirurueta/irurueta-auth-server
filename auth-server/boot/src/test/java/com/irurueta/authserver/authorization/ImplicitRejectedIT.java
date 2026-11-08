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

import static org.hamcrest.Matchers.endsWith;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.testsupport.PostgresIT;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

/**
 * Checks that, with the default profiles, the implicit flow does not exist: an authorization request with
 * {@code response_type=token} is refused with {@code 400 unsupported_response_type} and no redirect, for a public
 * client and for an unknown response type alike, and the legacy demo page is not served.
 */
@PostgresIT
@AutoConfigureMockMvc
class ImplicitRejectedIT {

    /** Path of the authorization endpoint. */
    private static final String AUTHORIZE = "/oauth2/authorize";

    /** Name of the parameter that carries the response type. */
    private static final String RESPONSE_TYPE = "response_type";

    /** Name of the parameter that carries the client identifier. */
    private static final String CLIENT_ID = "client_id";

    /** Name of the parameter that carries the redirect URI. */
    private static final String REDIRECT_URI = "redirect_uri";

    /** Error code expected. */
    private static final String UNSUPPORTED_RESPONSE_TYPE = "unsupported_response_type";

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

    /** Builds the clients. */
    private AuthServerFixtures fixtures;

    /**
     * Creates the fixtures.
     */
    @BeforeEach
    void createFixtures() {
        fixtures = new AuthServerFixtures(mockMvc, passwordEncoder, userAccounts, clientRegistrations);
    }

    /**
     * Verifies that a request for a token by a public client is refused without redirect.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorize_whenAPublicClientAsksForAToken_answersUnsupportedResponseType() throws Exception {
        final var client = fixtures.createCodeClient(List.of(), false);

        final var response = mockMvc.perform(get(AUTHORIZE).queryParam(RESPONSE_TYPE, "token")
                        .queryParam(CLIENT_ID, client.clientId())
                        .queryParam(REDIRECT_URI, AuthServerFixtures.REDIRECT_URI)
                        .queryParam("state", "abc"))
                .andExpect(status().isBadRequest()).andReturn().getResponse();

        assertNull(response.getRedirectedUrl());
        assertNotNull(response.getErrorMessage());
        assertTrue(response.getErrorMessage().contains(UNSUPPORTED_RESPONSE_TYPE));
    }

    /**
     * Verifies that an unknown response type is refused the same way.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorize_whenTheResponseTypeIsUnknown_answersUnsupportedResponseType() throws Exception {
        final var client = fixtures.createCodeClient(List.of(), false);

        final var response = mockMvc.perform(get(AUTHORIZE).queryParam(RESPONSE_TYPE, "id_token token")
                        .queryParam(CLIENT_ID, client.clientId())
                        .queryParam(REDIRECT_URI, AuthServerFixtures.REDIRECT_URI))
                .andExpect(status().isBadRequest()).andReturn().getResponse();

        assertNull(response.getRedirectedUrl());
        assertNotNull(response.getErrorMessage());
        assertTrue(response.getErrorMessage().contains(UNSUPPORTED_RESPONSE_TYPE));
    }

    /**
     * Verifies that the demo page of the legacy flow is not served without the profile: the request is sent to the
     * sign-in page like any other unknown protected path.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void demoPage_whenTheProfileIsNotActive_isNotServed() throws Exception {
        mockMvc.perform(get("/legacy-implicit/index.html"))
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", endsWith("/login")));
    }
}
