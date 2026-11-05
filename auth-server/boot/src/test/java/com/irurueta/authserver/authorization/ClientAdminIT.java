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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.api.web.password.PasswordConfiguration;
import com.irurueta.authserver.authorization.application.clients.SeedRegisteredClientsUseCase;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.testsupport.PostgresIT;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import tools.jackson.databind.JsonNode;

/**
 * Checks the registered-client features of the real application: idempotent seeding with encoded secrets, the
 * administration API, secret rotation and dynamic client registration (enabled for this test).
 */
@PostgresIT
@AutoConfigureMockMvc
class ClientAdminIT {

    /** Path of the client administration API. */
    private static final String CLIENTS_PATH = "/api/admin/clients";

    /** Secret seeded for the {@code bff} client, generated for this test run. */
    private static final String BFF_SEED_SECRET = AuthServerFixtures.randomValue();

    /** Prefix of an Argon2 hash in the delegating encoder's format. */
    private static final String ARGON2_PREFIX = "{" + PasswordConfiguration.DEFAULT_ENCODING_ID + "}";

    /** MockMvc bound to the application context. */
    @Autowired
    private MockMvc mockMvc;

    /** JDBC client that reads the stored rows. */
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

    /** Use case that seeds the default clients. */
    @Autowired
    private SeedRegisteredClientsUseCase seedUseCase;

    /** Fixtures of the test. */
    private AuthServerFixtures fixtures;

    /**
     * Seeds the {@code bff} client with the generated secret and enables dynamic client registration.
     *
     * @param registry registry of the test properties.
     */
    @DynamicPropertySource
    static void properties(final DynamicPropertyRegistry registry) {
        registry.add("authserver.clients.bff-secret", () -> BFF_SEED_SECRET);
        registry.add("authserver.oidc.client-registration.enabled", () -> "true");
    }

    /** Creates the fixtures. */
    @BeforeEach
    void setUp() {
        fixtures = new AuthServerFixtures(mockMvc, passwordEncoder, userAccounts, clientRegistrations);
    }

    /**
     * Verifies that the default clients exist after start, that seeding again creates nothing and that the stored
     * secret is encoded, never the raw value.
     */
    @Test
    void seeding_whenRepeated_isIdempotentAndStoresEncodedSecrets() {
        final var again = seedUseCase.execute(Map.of("bff", BFF_SEED_SECRET));

        assertEquals(List.of(), again.created());
        assertEquals(List.of(), again.skipped());
        assertEquals(1, count("bff"));
        assertEquals(1, count("spa-public"));
        final var stored = secretOf("bff");
        assertTrue(stored.startsWith(ARGON2_PREFIX));
        assertNotEquals(BFF_SEED_SECRET, stored);
        assertFalse(stored.contains(BFF_SEED_SECRET));
        assertTrue(passwordEncoder.matches(BFF_SEED_SECRET, stored));
        assertNull(secretOf("spa-public"), "a public client has no secret");
    }

    /**
     * Verifies the whole life of a client through the administration API.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void adminApi_whenClientIsCreatedUpdatedAndDeleted_followsTheCrudContract() throws Exception {
        final var admin = fixtures.adminToken();
        final var clientId = "managed-" + UUID.randomUUID();

        final var created = body(send(post(CLIENTS_PATH), admin, clientJson(clientId, "Managed"))
                .andExpect(status().isCreated()));
        final var issued = created.get("clientSecret").asString();
        assertEquals(clientId, created.get("client").get("clientId").asString());
        assertTrue(passwordEncoder.matches(issued, secretOf(clientId)));
        assertFalse(secretOf(clientId).contains(issued));

        final var fetched = body(mockMvc.perform(get(CLIENTS_PATH + "/" + clientId).header(
                        AuthServerFixtures.AUTHORIZATION, "Bearer " + admin))
                .andExpect(status().isOk()));
        assertEquals("Managed", fetched.get("name").asString());
        assertFalse(fetched.has("clientSecret"), "the secret is only shown on creation");
        mockMvc.perform(get(CLIENTS_PATH).header(AuthServerFixtures.AUTHORIZATION, "Bearer " + admin))
                .andExpect(status().isOk())
                .andExpect(content().string(containsString(clientId)));

        send(post(CLIENTS_PATH), admin, clientJson(clientId, "Managed")).andExpect(status().isConflict());

        final var updated = body(send(put(CLIENTS_PATH + "/" + clientId), admin, clientJson(clientId, "Renamed"))
                .andExpect(status().isOk()));
        assertEquals("Renamed", updated.get("name").asString());
        assertTrue(passwordEncoder.matches(issued, secretOf(clientId)), "updating keeps the secret");
        send(put(CLIENTS_PATH + "/other"), admin, clientJson(clientId, "Renamed"))
                .andExpect(status().isBadRequest());

        mockMvc.perform(delete(CLIENTS_PATH + "/" + clientId).header(AuthServerFixtures.AUTHORIZATION,
                "Bearer " + admin)).andExpect(status().isNoContent());
        assertEquals(0, count(clientId));
        mockMvc.perform(get(CLIENTS_PATH + "/" + clientId).header(AuthServerFixtures.AUTHORIZATION,
                "Bearer " + admin)).andExpect(status().isNotFound());
    }

    /**
     * Verifies that rotating the secret returns a new one, stores it encoded and stops the old one working.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void rotateSecret_whenCalled_replacesTheSecret() throws Exception {
        final var admin = fixtures.adminToken();
        final var clientId = "rotating-" + UUID.randomUUID();
        final var issued = body(send(post(CLIENTS_PATH), admin, clientJson(clientId, "Rotating"))
                .andExpect(status().isCreated())).get("clientSecret").asString();
        tokenRequest(clientId, issued).andExpect(status().isOk());

        final var replacement = body(mockMvc.perform(post(CLIENTS_PATH + "/" + clientId + "/secret")
                        .header(AuthServerFixtures.AUTHORIZATION, "Bearer " + admin))
                .andExpect(status().isOk())).get("clientSecret").asString();

        assertNotEquals(issued, replacement);
        assertTrue(passwordEncoder.matches(replacement, secretOf(clientId)));
        tokenRequest(clientId, issued).andExpect(status().isUnauthorized());
        tokenRequest(clientId, replacement).andExpect(status().isOk());
    }

    /**
     * Verifies that the API needs the admin scope.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void adminApi_whenCallerIsNotAnAdmin_isRejected() throws Exception {
        final var reader = fixtures.clientCredentialsToken(fixtures.createClient(
                List.of("client_credentials"), List.of("read"), List.of("auth-server")), "read");

        mockMvc.perform(get(CLIENTS_PATH)).andExpect(status().isUnauthorized());
        mockMvc.perform(get(CLIENTS_PATH).header(AuthServerFixtures.AUTHORIZATION, "Bearer " + reader))
                .andExpect(status().isForbidden());
    }

    /**
     * Verifies that, with dynamic registration enabled, a caller holding an initial access token with the
     * {@code client.create} scope registers a client whose secret is stored encoded.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void dynamicRegistration_whenEnabledAndTokenHasTheScope_registersAClientWithAnEncodedSecret() throws Exception {
        final var initial = fixtures.clientCredentialsToken(fixtures.createClient(
                List.of("client_credentials"), List.of("client.create"), List.of("auth-server")), "client.create");
        final var request = """
                {"client_name":"Dynamic","redirect_uris":["%s"],"grant_types":["authorization_code"],
                 "token_endpoint_auth_method":"client_secret_basic"}
                """.formatted(AuthServerFixtures.REDIRECT_URI);

        final var registered = body(mockMvc.perform(post("/connect/register")
                        .header(AuthServerFixtures.AUTHORIZATION, "Bearer " + initial)
                        .contentType(MediaType.APPLICATION_JSON).content(request))
                .andExpect(status().isCreated()));

        final var clientId = registered.get("client_id").asString();
        final var issued = registered.get("client_secret").asString();
        assertNotNull(clientId);
        assertTrue(passwordEncoder.matches(issued, secretOf(clientId)));
        assertFalse(secretOf(clientId).contains(issued));
    }

    /**
     * Verifies that dynamic registration needs an initial access token.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void dynamicRegistration_whenThereIsNoToken_isRejected() throws Exception {
        mockMvc.perform(post("/connect/register").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"client_name\":\"x\",\"redirect_uris\":[\"" + AuthServerFixtures.REDIRECT_URI
                                + "\"]}"))
                .andExpect(status().is3xxRedirection());
    }

    /**
     * Sends a JSON body with an admin token.
     *
     * @param builder the request.
     * @param admin   admin access token.
     * @param json    JSON body.
     * @return the result of the request.
     * @throws Exception if the request cannot be performed.
     */
    private ResultActions send(final MockHttpServletRequestBuilder builder,
                               final String admin, final String json) throws Exception {
        return mockMvc.perform(builder.header(AuthServerFixtures.AUTHORIZATION, "Bearer " + admin)
                .contentType(MediaType.APPLICATION_JSON).content(json));
    }

    /**
     * Requests a client credentials token with the given client credentials.
     *
     * @param clientId   identifier of the client.
     * @param credential credential of the client.
     * @return the result of the request.
     * @throws Exception if the request cannot be performed.
     */
    private ResultActions tokenRequest(final String clientId, final String credential) throws Exception {
        return mockMvc.perform(post(AuthServerFixtures.TOKEN_PATH)
                .header(AuthServerFixtures.AUTHORIZATION, AuthServerFixtures.basic(clientId, credential))
                .param(AuthServerFixtures.GRANT_TYPE, "client_credentials").param("scope", "read"));
    }

    /**
     * Reads the JSON body of an answer.
     *
     * @param result the answer.
     * @return the body.
     * @throws Exception if the body cannot be read.
     */
    private static JsonNode body(final ResultActions result) throws Exception {
        return AuthServerFixtures.parse(result.andReturn().getResponse().getContentAsString());
    }

    /**
     * Builds the request body of a confidential client with the client credentials grant.
     *
     * @param clientId identifier of the client.
     * @param name     display name of the client.
     * @return the JSON body.
     */
    private static String clientJson(final String clientId, final String name) {
        return """
                {"clientId":"%s","name":"%s","confidential":true,"authMethods":["client_secret_basic"],
                 "grantTypes":["client_credentials"],"redirectUris":[],"scopes":["read"],"requireProofKey":false,
                 "audiences":["resource-server"],"accessTokenTtl":"PT10M","refreshTokenTtl":"PT1H",
                 "accessTokenFormat":"self-contained","reuseRefreshTokens":false}
                """.formatted(clientId, name);
    }

    /**
     * Counts the stored rows of a client.
     *
     * @param clientId identifier of the client.
     * @return the number of rows.
     */
    private int count(final String clientId) {
        return jdbcClient.sql("SELECT count(*) FROM oauth2_registered_client WHERE client_id = ?").param(clientId)
                .query(Integer.class).single();
    }

    /**
     * Reads the stored secret of a client.
     *
     * @param clientId identifier of the client.
     * @return the stored secret, or {@code null} for a public client.
     */
    private String secretOf(final String clientId) {
        return jdbcClient.sql("SELECT client_secret FROM oauth2_registered_client WHERE client_id = ?")
                .param(clientId).query(String.class).optional().orElse(null);
    }
}
