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
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.AuthServerFixtures.TestClient;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.testsupport.PostgresIT;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.test.web.servlet.MockMvc;
import tools.jackson.databind.JsonNode;

/**
 * Checks the token endpoints of the real application: the custom claims, refresh-token rotation and reuse
 * detection, revocation, introspection and the UserInfo endpoint.
 */
@PostgresIT(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class TokenFlowIT {

    /** Path of the introspection endpoint. */
    private static final String INTROSPECT_PATH = "/oauth2/introspect";

    /** Path of the revocation endpoint. */
    private static final String REVOKE_PATH = "/oauth2/revoke";

    /** Name of the parameter that carries a token. */
    private static final String TOKEN = "token";

    /** Name of the answer field that carries the refresh token. */
    private static final String REFRESH_TOKEN = "refresh_token";

    /** Name of the answer field that carries the access token. */
    private static final String ACCESS_TOKEN = "access_token";

    /** MockMvc bound to the application context. */
    @Autowired
    private MockMvc mockMvc;

    /** JDBC client that counts the stored authorizations. */
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

    /** Port the application listens on. */
    @LocalServerPort
    private int port;

    /** Fixtures of the test. */
    private AuthServerFixtures fixtures;

    /** Creates the fixtures. */
    @BeforeEach
    void setUp() {
        fixtures = new AuthServerFixtures(mockMvc, passwordEncoder, userAccounts, clientRegistrations);
    }

    /**
     * Verifies that the access token carries the audience of the client, the roles and the tenant of the user.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void accessToken_whenIssuedToAUser_carriesAudienceRolesAndTenant() throws Exception {
        final var user = fixtures.createUser();
        final var tokens = fixtures.authorizationCodeTokens(user, fixtures.createCodeClient());

        final var claims = NimbusJwtDecoder.withJwkSetUri("http://localhost:" + port + "/oauth2/jwks").build()
                .decode(tokens.get(ACCESS_TOKEN).asString());

        assertEquals(user.username(), claims.getSubject());
        assertEquals(List.of(AuthServerFixtures.RESOURCE_SERVER_AUDIENCE, AuthServerFixtures.API_AUDIENCE),
                claims.getAudience());
        assertEquals(List.of("ROLE_USER"), claims.getClaimAsStringList("roles"));
        assertEquals(AuthServerFixtures.TENANT, claims.getClaimAsString("tenant"));
        assertTrue(claims.getClaimAsStringList("scope").containsAll(List.of("openid", "profile", "email")));
    }

    /**
     * Verifies that a client credentials token has the audience of the client and no user claims.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void accessToken_whenIssuedToAClient_hasAudienceButNoUserClaims() throws Exception {
        final var client = fixtures.createClient(List.of("client_credentials"), List.of("read"),
                List.of("resource-server"));

        final var claims = NimbusJwtDecoder.withJwkSetUri("http://localhost:" + port + "/oauth2/jwks").build()
                .decode(fixtures.clientCredentialsToken(client, "read"));

        assertEquals(List.of("resource-server"), claims.getAudience());
        assertFalse(claims.hasClaim("roles"));
        assertFalse(claims.hasClaim("tenant"));
    }

    /**
     * Verifies that refreshing issues a new access token and a new refresh token, and keeps the authorization.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void refresh_whenTokenIsValid_rotatesTheRefreshToken() throws Exception {
        final var user = fixtures.createUser();
        final var client = fixtures.createCodeClient();
        final var tokens = fixtures.authorizationCodeTokens(user, client);

        final var refreshed = refresh(client, tokens.get(REFRESH_TOKEN).asString())
                .andExpectStatusOk();

        assertNotEquals(tokens.get(REFRESH_TOKEN).asString(), refreshed.get(REFRESH_TOKEN).asString());
        assertNotEquals(tokens.get(ACCESS_TOKEN).asString(), refreshed.get(ACCESS_TOKEN).asString());
        assertEquals(1, authorizationCount(user.username()));
    }

    // tag::tokens-reuse-it[]
    /**
     * Verifies that presenting a rotated refresh token again fails and revokes the whole authorization, so the
     * legitimate new refresh token stops working too.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void refresh_whenRotatedTokenIsReused_revokesTheAuthorization() throws Exception {
        final var user = fixtures.createUser();
        final var client = fixtures.createCodeClient();
        final var tokens = fixtures.authorizationCodeTokens(user, client);
        final var rotated = tokens.get(REFRESH_TOKEN).asString();
        final var current = refresh(client, rotated).andExpectStatusOk().get(REFRESH_TOKEN).asString();

        refresh(client, rotated).andExpectBadRequest();

        assertEquals(0, authorizationCount(user.username()));
        refresh(client, current).andExpectBadRequest();
    }
    // end::tokens-reuse-it[]

    /**
     * Verifies that a revoked access token is introspected as inactive.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void revoke_whenAccessTokenIsRevoked_introspectionTurnsInactive() throws Exception {
        final var client = fixtures.createCodeClient();
        final var tokens = fixtures.authorizationCodeTokens(fixtures.createUser(), client);
        final var accessToken = tokens.get(ACCESS_TOKEN).asString();
        assertTrue(introspect(client, accessToken).get("active").asBoolean());

        mockMvc.perform(post(REVOKE_PATH)
                        .header(AuthServerFixtures.AUTHORIZATION,
                                AuthServerFixtures.basic(client.clientId(), client.credential()))
                        .param(TOKEN, accessToken))
                .andExpect(status().isOk());

        assertFalse(introspect(client, accessToken).get("active").asBoolean());
    }

    /**
     * Verifies that a revoked refresh token can no longer be used.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void revoke_whenRefreshTokenIsRevoked_itCannotBeUsed() throws Exception {
        final var client = fixtures.createCodeClient();
        final var tokens = fixtures.authorizationCodeTokens(fixtures.createUser(), client);

        mockMvc.perform(post(REVOKE_PATH)
                        .header(AuthServerFixtures.AUTHORIZATION,
                                AuthServerFixtures.basic(client.clientId(), client.credential()))
                        .param(TOKEN, tokens.get(REFRESH_TOKEN).asString())
                        .param("token_type_hint", REFRESH_TOKEN))
                .andExpect(status().isOk());

        refresh(client, tokens.get(REFRESH_TOKEN).asString()).andExpectBadRequest();
    }

    /**
     * Verifies that introspection describes an active token and reports an unknown one as inactive.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void introspect_whenTokenIsActiveOrUnknown_reportsIt() throws Exception {
        final var user = fixtures.createUser();
        final var client = fixtures.createCodeClient();
        final var tokens = fixtures.authorizationCodeTokens(user, client);

        final var active = introspect(client, tokens.get(ACCESS_TOKEN).asString());
        final var unknown = introspect(client, AuthServerFixtures.randomValue());

        assertTrue(active.get("active").asBoolean());
        assertEquals(user.username(), active.get("sub").asString());
        assertEquals(client.clientId(), active.get("client_id").asString());
        assertFalse(unknown.get("active").asBoolean());
    }

    /**
     * Verifies that a reference (opaque) access token carries the same claims as a JWT one: introspected by another
     * client (as a resource server does), it lists the client's audiences, the roles and the tenant of the user.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void introspect_whenTokenIsAReferenceToken_returnsAudienceRolesAndTenant() throws Exception {
        final var user = fixtures.createUser();
        final var client = fixtures.createClient(List.of("authorization_code", "refresh_token"),
                List.of("openid", "profile", "email"), List.of(AuthServerFixtures.RESOURCE_SERVER_AUDIENCE),
                ClientRegistration.FORMAT_REFERENCE);
        final var accessToken = fixtures.authorizationCodeTokens(user, client).get(ACCESS_TOKEN).asString();
        assertFalse(accessToken.contains("."), "a reference token is not a JWT");
        final var resourceServer = fixtures.createClient(List.of("client_credentials"), List.of("read"),
                List.of(AuthServerFixtures.API_AUDIENCE));

        final var introspected = introspect(resourceServer, accessToken);

        assertTrue(introspected.get("active").asBoolean());
        assertEquals(user.username(), introspected.get("sub").asString());
        assertEquals(List.of(AuthServerFixtures.RESOURCE_SERVER_AUDIENCE), strings(introspected.get("aud")));
        assertEquals(List.of("ROLE_USER"), strings(introspected.get("roles")));
        assertEquals(AuthServerFixtures.TENANT, introspected.get("tenant").asString());
    }

    /**
     * Verifies that the UserInfo endpoint answers with the claims the granted scopes allow.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void userInfo_whenScopesAreGranted_containsProfileAndEmailClaims() throws Exception {
        final var user = fixtures.createUser();
        final var tokens = fixtures.authorizationCodeTokens(user, fixtures.createCodeClient());

        final var body = mockMvc.perform(get("/userinfo")
                        .header(AuthServerFixtures.AUTHORIZATION, "Bearer " + tokens.get(ACCESS_TOKEN).asString()))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

        final var info = AuthServerFixtures.parse(body);
        assertEquals(user.username(), info.get("sub").asString());
        assertEquals(user.username(), info.get("preferred_username").asString());
        assertEquals(AuthServerFixtures.TENANT, info.get("tenant").asString());
        assertEquals("ROLE_USER", info.get("roles").get(0).asString());
        assertEquals(user.email(), info.get("email").asString());
        assertTrue(info.get("email_verified").asBoolean());
    }

    /**
     * Verifies that the UserInfo endpoint sends an anonymous browser-less request to the login page and answers a
     * request with an invalid bearer token with a {@code 401} challenge.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void userInfo_whenTokenIsMissingOrInvalid_isRejected() throws Exception {
        mockMvc.perform(get("/userinfo")).andExpect(status().is3xxRedirection());
        mockMvc.perform(get("/userinfo").header(AuthServerFixtures.AUTHORIZATION,
                        "Bearer " + AuthServerFixtures.randomValue()))
                .andExpect(status().isUnauthorized());
    }

    /**
     * Reads a JSON array of strings.
     *
     * @param array the array.
     * @return its values.
     */
    private static List<String> strings(final JsonNode array) {
        final var values = new ArrayList<String>();
        array.forEach(value -> values.add(value.asString()));
        return values;
    }

    /**
     * Introspects a token with the credentials of a client.
     *
     * @param client the client.
     * @param token  the token.
     * @return the answer.
     * @throws Exception if the request cannot be performed.
     */
    private JsonNode introspect(final TestClient client, final String token) throws Exception {
        final var body = mockMvc.perform(post(INTROSPECT_PATH)
                        .header(AuthServerFixtures.AUTHORIZATION,
                                AuthServerFixtures.basic(client.clientId(), client.credential()))
                        .param(TOKEN, token))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return AuthServerFixtures.parse(body);
    }

    /**
     * Performs a refresh token request.
     *
     * @param client       the client.
     * @param refreshToken the refresh token to present.
     * @return the pending answer.
     * @throws Exception if the request cannot be performed.
     */
    private RefreshResult refresh(final TestClient client, final String refreshToken) throws Exception {
        return new RefreshResult(mockMvc.perform(post(AuthServerFixtures.TOKEN_PATH)
                        .header(AuthServerFixtures.AUTHORIZATION,
                                AuthServerFixtures.basic(client.clientId(), client.credential()))
                        .param(AuthServerFixtures.GRANT_TYPE, REFRESH_TOKEN)
                        .param(REFRESH_TOKEN, refreshToken))
                .andReturn().getResponse());
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
     * The answer to a refresh token request.
     *
     * @param response the HTTP response.
     */
    private record RefreshResult(MockHttpServletResponse response) {

        /**
         * Expects a successful answer.
         *
         * @return the token endpoint answer.
         * @throws UnsupportedEncodingException if the body cannot be decoded.
         */
        JsonNode andExpectStatusOk() throws UnsupportedEncodingException {
            assertEquals(HttpStatus.OK.value(), response.getStatus());
            return AuthServerFixtures.parse(response.getContentAsString());
        }

        /**
         * Expects the {@code invalid_grant} answer.
         *
         * @throws UnsupportedEncodingException if the body cannot be decoded.
         */
        void andExpectBadRequest() throws UnsupportedEncodingException {
            assertEquals(HttpStatus.BAD_REQUEST.value(), response.getStatus());
            assertEquals("invalid_grant", AuthServerFixtures.parse(response.getContentAsString())
                    .get("error").asString());
        }
    }
}
