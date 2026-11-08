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
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.testsupport.PostgresIT;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

/**
 * Drives the legacy implicit flow, enabled only by the {@code legacy-implicit} profile: the token comes back in the
 * fragment of the one registered redirect URI, short-lived, without refresh token and introspectable; any other client,
 * an unregistered redirect URI or a missing {@code state} is refused; the authorization code flow keeps working; and
 * the demo page is served.
 */
@PostgresIT
@ActiveProfiles({"test", "legacy-implicit"})
@AutoConfigureMockMvc
class LegacyImplicitIT {

    /** Path of the authorization endpoint. */
    private static final String AUTHORIZE = "/oauth2/authorize";

    /** Client of the legacy flow, as configured in {@code application-legacy-implicit.yml}. */
    private static final String LEGACY_CLIENT = "legacy-implicit-spa";

    /** Redirect URI of the legacy client, as configured in {@code application-legacy-implicit.yml}. */
    private static final String LEGACY_REDIRECT = "http://localhost:9000/legacy-implicit/";

    /** Scope of the legacy client. */
    private static final String SCOPE = "documents.read";

    /** State of the requests. */
    private static final String STATE = "state-value";

    /** Longest lifetime expected of the token, in seconds. */
    private static final long MAX_EXPIRES_IN = 300;

    /** Lifetime of the tokens of the public client of the code flow. */
    private static final Duration TOKEN_TTL = Duration.ofMinutes(10);

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

    /** Builds the users and clients. */
    private AuthServerFixtures fixtures;

    /** The signed-in user. */
    private AuthServerFixtures.TestUser user;

    /** The browser session of the user. */
    private MockHttpSession session;

    /**
     * Creates a user who is signed in.
     *
     * @throws Exception if the sign-in cannot be performed.
     */
    @BeforeEach
    void signIn() throws Exception {
        fixtures = new AuthServerFixtures(mockMvc, passwordEncoder, userAccounts, clientRegistrations);
        user = fixtures.createUser();
        session = new MockHttpSession();
        fixtures.signIn(user, session);
    }

    /**
     * Verifies that the token comes back in the fragment: Bearer, short-lived, with the resource server audience, the
     * requested scope and the state, without refresh token, and that it can be introspected.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorize_whenTheLegacyClientAsksForAToken_redirectsWithTheTokenInTheFragment() throws Exception {
        final var response = mockMvc.perform(authorize(LEGACY_CLIENT, LEGACY_REDIRECT, STATE))
                .andExpect(status().isFound())
                .andExpect(header().string("Cache-Control", containsString("no-store")))
                .andExpect(header().string("Referrer-Policy", "no-referrer"))
                .andReturn().getResponse();

        final var location = response.getRedirectedUrl();
        assertNotNull(location);
        assertTrue(location.startsWith(LEGACY_REDIRECT + "#"));
        final var uri = UriComponentsBuilder.fromUriString(location).build();
        assertNull(uri.getQuery());
        final var fragment = fragmentOf(uri.getFragment());
        assertEquals("Bearer", fragment.get("token_type"));
        assertEquals(SCOPE, fragment.get("scope"));
        assertEquals(STATE, fragment.get("state"));
        assertTrue(Long.parseLong(fragment.get("expires_in")) <= MAX_EXPIRES_IN);
        assertFalse(fragment.containsKey("refresh_token"));
        final var token = fragment.get("access_token");
        assertNotNull(token);
        final var claims = AuthServerFixtures.claimsOf(token);
        assertEquals(user.username(), claims.get("sub").asString());
        assertTrue(claims.get("aud").toString().contains(AuthServerFixtures.RESOURCE_SERVER_AUDIENCE));
        final var introspector = fixtures.createClient(List.of("client_credentials"), List.of("read"),
                List.of(AuthServerFixtures.API_AUDIENCE));
        mockMvc.perform(post("/oauth2/introspect")
                        .header(AuthServerFixtures.AUTHORIZATION,
                                AuthServerFixtures.basic(introspector.clientId(), introspector.credential()))
                        .param("token", token))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("\"active\":true")));
    }

    /**
     * Verifies that a public client of the code flow cannot use the implicit flow.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorize_whenAnotherClientAsksForAToken_answersUnsupportedResponseType() throws Exception {
        final var clientId = "spa-public-" + UUID.randomUUID();
        clientRegistrations.save(new ClientRegistration(clientId, "Public SPA", false, List.of("none"),
                List.of("authorization_code"), List.of(AuthServerFixtures.REDIRECT_URI), List.of(SCOPE), true,
                List.of(AuthServerFixtures.RESOURCE_SERVER_AUDIENCE), TOKEN_TTL, TOKEN_TTL,
                ClientRegistration.FORMAT_SELF_CONTAINED, false, List.of(), false, false, null, null, null, null,
                false), null);

        final var response = mockMvc.perform(authorize(clientId, AuthServerFixtures.REDIRECT_URI, STATE))
                .andExpect(status().isBadRequest()).andReturn().getResponse();

        assertNull(response.getRedirectedUrl());
        assertNotNull(response.getErrorMessage());
        assertTrue(response.getErrorMessage().contains("unsupported_response_type"));
    }

    /**
     * Verifies that a redirect URI that is not exactly the registered one gets no redirect, so no token is sent
     * anywhere.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorize_whenTheRedirectUriIsNotRegistered_doesNotRedirect() throws Exception {
        final var response = mockMvc.perform(authorize(LEGACY_CLIENT, "http://evil.example/cb", STATE))
                .andExpect(status().isBadRequest()).andReturn().getResponse();

        assertNull(response.getRedirectedUrl());
    }

    /**
     * Verifies that a request without {@code state} is refused in the fragment of the registered redirect URI.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorize_whenStateIsMissing_redirectsWithInvalidRequestInTheFragment() throws Exception {
        final var response = mockMvc.perform(authorize(LEGACY_CLIENT, LEGACY_REDIRECT, null))
                .andExpect(status().isFound()).andReturn().getResponse();

        final var location = response.getRedirectedUrl();
        assertNotNull(location);
        assertTrue(location.startsWith(LEGACY_REDIRECT + "#error=invalid_request"));
        assertFalse(location.contains("access_token"));
    }

    /**
     * Verifies that the authorization code flow still works next to the legacy one.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorize_whenTheCodeFlowIsUsed_stillIssuesTokens() throws Exception {
        final var client = fixtures.createCodeClient(List.of(), false);

        final var tokens = fixtures.authorizationCodeTokens(user, client);

        assertNotNull(tokens.get("access_token"));
    }

    /**
     * Verifies that the demo page and its script are served, and that the directory path shows the page.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void demoPage_whenTheProfileIsActive_isServed() throws Exception {
        mockMvc.perform(get("/legacy-implicit/index.html"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("legacy-implicit.js")));
        mockMvc.perform(get("/legacy-implicit/legacy-implicit.js"))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("sessionStorage")));
        mockMvc.perform(get("/legacy-implicit/"))
                .andExpect(forwardedUrl("/legacy-implicit/index.html"));
    }

    /**
     * Builds an authorization request for a token, as the signed-in user.
     *
     * @param clientId    the client.
     * @param redirectUri the redirect URI.
     * @param state       the state, {@code null} to omit it.
     * @return the request.
     */
    private MockHttpServletRequestBuilder authorize(final String clientId, final String redirectUri,
            final String state) {
        final var request = get(AUTHORIZE).session(session).queryParam("response_type", "token")
                .queryParam("client_id", clientId).queryParam("redirect_uri", redirectUri)
                .queryParam("scope", SCOPE);
        return state == null ? request : request.queryParam("state", state);
    }

    /**
     * Splits and decodes the fragment of a redirect.
     *
     * @param fragment the encoded fragment.
     * @return its parameters.
     */
    private static Map<String, String> fragmentOf(final String fragment) {
        assertNotNull(fragment);
        final var parameters = new HashMap<String, String>();
        for (final var pair : fragment.split("&")) {
            final var parts = pair.split("=", 2);
            parameters.put(parts[0], UriUtils.decode(parts[1], StandardCharsets.UTF_8));
        }
        return parameters;
    }
}
