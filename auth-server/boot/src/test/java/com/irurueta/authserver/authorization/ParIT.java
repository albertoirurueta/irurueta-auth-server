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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.AuthServerFixtures.TestClient;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.testsupport.PostgresIT;
import java.util.Map;
import java.util.Objects;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.JsonNode;

/**
 * Checks pushed authorization requests (RFC 9126) of the real application: the endpoint does not exist unless
 * {@code authserver.par.enabled} is set and, when it is, a pushed request completes the authorization code flow, keeps
 * the multi-factor policy and cannot be used twice.
 */
@PostgresIT
@AutoConfigureMockMvc
class ParIT {

    /** Path of the pushed authorization request endpoint. */
    private static final String PAR_PATH = "/oauth2/par";

    /** Name of the metadata field that advertises the endpoint. */
    private static final String PAR_METADATA = "pushed_authorization_request_endpoint";

    /** Name of the parameter that carries a pushed request's reference. */
    private static final String REQUEST_URI = "request_uri";

    /** MockMvc bound to the application context. */
    @Autowired
    private MockMvc mockMvc;

    /** Encoder of the application. */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /** Port that stores user accounts. */
    @Autowired
    private UserAccountRepository userAccounts;

    /** Port that stores client registrations. */
    @Autowired
    private ClientRegistrationRepository clientRegistrations;

    /** Fixtures of the test. */
    private AuthServerFixtures fixtures;

    /** Creates the fixtures. */
    @BeforeEach
    void setUp() {
        fixtures = new AuthServerFixtures(mockMvc, passwordEncoder, userAccounts, clientRegistrations);
    }

    /**
     * Without the property the endpoint is not found and the metadata does not advertise it.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void par_whenDisabled_endpointIsNotFoundAndNotAdvertised() throws Exception {
        final var client = fixtures.createCodeClient();

        push(client, "verifier-" + AuthServerFixtures.randomValue()).andExpect(status().isNotFound());

        final var metadata = AuthServerFixtures.parse(mockMvc.perform(get("/.well-known/openid-configuration"))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
        assertFalse(metadata.has(PAR_METADATA));
    }

    /**
     * Pushes an authorization request.
     *
     * @param client   the client that pushes it.
     * @param verifier PKCE code verifier of the request.
     * @return the result actions.
     * @throws Exception if the request cannot be performed.
     */
    private ResultActions push(final TestClient client, final String verifier) throws Exception {
        final var uri = UriComponentsBuilder.fromUriString(AuthServerFixtures.authorizeUri(client, verifier,
                Map.of())).build();
        final var request = post(PAR_PATH).header(AuthServerFixtures.AUTHORIZATION,
                AuthServerFixtures.basic(client.clientId(), client.credential()));
        uri.getQueryParams().forEach((name, values) -> request.param(name, values.getFirst()));
        return mockMvc.perform(request);
    }

    /**
     * Pushes a request that must be accepted.
     *
     * @param client   the client that pushes it.
     * @param verifier PKCE code verifier of the request.
     * @return the {@code request_uri} of the answer.
     * @throws Exception if the request cannot be performed.
     */
    private String pushed(final TestClient client, final String verifier) throws Exception {
        final JsonNode answer = AuthServerFixtures.parse(push(client, verifier).andExpect(status().isCreated())
                .andReturn().getResponse().getContentAsString());
        final var requestUri = answer.get(REQUEST_URI).asString();
        assertTrue(requestUri.startsWith("urn:ietf:params:oauth:request_uri:"));
        return requestUri;
    }

    /**
     * Authorizes with a pushed request. The framework reads a {@code GET} from the query string, so the parameters
     * are query parameters.
     *
     * @param client     the client.
     * @param requestUri the reference of the pushed request.
     * @param session    the browser session.
     * @return the result actions.
     * @throws Exception if the request cannot be performed.
     */
    private ResultActions authorize(final TestClient client, final String requestUri, final MockHttpSession session)
            throws Exception {
        return mockMvc.perform(get("/oauth2/authorize").session(session)
                .queryParam("client_id", client.clientId()).queryParam(REQUEST_URI, requestUri));
    }

    /**
     * With the property set, the pushed-request tests run in a context where the endpoint exists. The nested class
     * inherits the annotations of the test and stays package-private, as the framework requires.
     */
    @Nested
    @TestPropertySource(properties = "authserver.par.enabled=true")
    class WhenEnabled {

        /**
         * The endpoint answers {@code 201} with a request URI and the metadata advertises it.
         *
         * @throws Exception if a request cannot be performed.
         */
        @Test
        void par_whenEnabled_answersRequestUriAndIsAdvertised() throws Exception {
            final var client = fixtures.createCodeClient();

            final var requestUri = pushed(client, AuthServerFixtures.randomValue() + AuthServerFixtures.randomValue());

            assertNotNull(requestUri);
            final var metadata = AuthServerFixtures.parse(mockMvc.perform(get("/.well-known/openid-configuration"))
                    .andExpect(status().isOk()).andReturn().getResponse().getContentAsString());
            assertTrue(metadata.get(PAR_METADATA).asString().endsWith(PAR_PATH));
        }

        /**
         * Authorizing with the {@code request_uri} completes the code flow.
         *
         * @throws Exception if a request cannot be performed.
         */
        @Test
        void authorize_whenRequestUriIsPushed_completesTheCodeFlow() throws Exception {
            final var user = fixtures.createUser();
            final var client = fixtures.createCodeClient();
            final var verifier = AuthServerFixtures.randomValue() + AuthServerFixtures.randomValue();
            final var requestUri = pushed(client, verifier);
            final var session = new MockHttpSession();

            authorize(client, requestUri, session).andExpect(status().is3xxRedirection());
            fixtures.signIn(user, session);
            final var authorized = authorize(client, requestUri, session).andExpect(status().is3xxRedirection())
                    .andReturn();

            final var tokens = fixtures.exchangeCode(client, AuthServerFixtures.codeOf(authorized), verifier);
            assertNotNull(tokens.get("access_token"));
        }

        /**
         * The multi-factor policy of the client still applies to a pushed request.
         *
         * @throws Exception if a request cannot be performed.
         */
        @Test
        void authorize_whenClientRequiresMfa_sendsToTheSecondFactorPage() throws Exception {
            final var user = fixtures.createUser();
            final var client = fixtures.createMfaCodeClient();
            final var requestUri = pushed(client, AuthServerFixtures.randomValue() + AuthServerFixtures.randomValue());
            final var session = new MockHttpSession();

            authorize(client, requestUri, session).andExpect(status().is3xxRedirection());
            fixtures.signIn(user, session);
            final var authorized = authorize(client, requestUri, session).andExpect(status().is3xxRedirection())
                    .andReturn();

            final var location = Objects.requireNonNull(authorized.getResponse().getRedirectedUrl());
            assertTrue(location.contains("/login/second-factor"), location);
            assertFalse(location.contains("code="));
        }

        /**
         * A {@code request_uri} that was already used to obtain a code is refused.
         *
         * @throws Exception if a request cannot be performed.
         */
        @Test
        void authorize_whenRequestUriIsReused_isRefused() throws Exception {
            final var user = fixtures.createUser();
            final var client = fixtures.createCodeClient();
            final var requestUri = pushed(client, AuthServerFixtures.randomValue() + AuthServerFixtures.randomValue());
            final var session = new MockHttpSession();
            authorize(client, requestUri, session).andExpect(status().is3xxRedirection());
            fixtures.signIn(user, session);
            authorize(client, requestUri, session).andExpect(status().is3xxRedirection());

            final var again = authorize(client, requestUri, session).andReturn().getResponse();

            final var location = again.getRedirectedUrl();
            assertTrue(again.getStatus() == HttpStatus.BAD_REQUEST.value()
                    || location != null && location.contains("error="));
            assertFalse(location != null && location.contains("code="));
        }
    }
}
