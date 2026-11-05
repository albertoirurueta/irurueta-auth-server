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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Builds the users and clients the integration tests need and drives the protocol endpoints of the running
 * application through MockMvc. Every credential is generated at runtime, so no test stores one.
 */
@RequiredArgsConstructor
final class AuthServerFixtures {

    /** Redirect URI of the generated clients. */
    static final String REDIRECT_URI = "http://127.0.0.1:8080/callback";

    /** Path of the token endpoint. */
    static final String TOKEN_PATH = "/oauth2/token";

    /** Name of the request header that carries credentials. */
    static final String AUTHORIZATION = "Authorization";

    /** Name of the token endpoint parameter that carries the grant type. */
    static final String GRANT_TYPE = "grant_type";

    /** Audience of the resource server. */
    static final String RESOURCE_SERVER_AUDIENCE = "resource-server";

    /** Audience of this server's own API. */
    static final String API_AUDIENCE = "auth-server";

    /** Tenant of the generated users. */
    static final String TENANT = "acme";

    /** Number of random bytes of generated values. */
    private static final int RANDOM_BYTES = 32;

    /** Lifetime of the tokens of the generated clients. */
    private static final Duration TOKEN_TTL = Duration.ofMinutes(10);

    /** Lifetime of the refresh tokens of the generated clients. */
    private static final Duration REFRESH_TTL = Duration.ofHours(1);

    /** Reads the JSON answers. */
    private static final JsonMapper JSON = JsonMapper.builder().build();

    /** MockMvc bound to the application context. */
    private final MockMvc mockMvc;

    /** Encoder of the application. */
    private final PasswordEncoder passwordEncoder;

    /** Port that stores user accounts. */
    private final UserAccountRepository userAccounts;

    /** Port that stores client registrations. */
    private final ClientRegistrationRepository clientRegistrations;

    /**
     * Generates a random URL-safe value.
     *
     * @return the value.
     */
    static String randomValue() {
        final var bytes = new byte[RANDOM_BYTES];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Builds the value of a basic authentication header.
     *
     * @param clientId   identifier of the client.
     * @param credential credential of the client.
     * @return the header value.
     */
    static String basic(final String clientId, final String credential) {
        return "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":" + credential).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Parses a JSON document.
     *
     * @param json the document.
     * @return its tree.
     */
    static JsonNode parse(final String json) {
        return JSON.readTree(json);
    }

    /**
     * Creates an enabled user with one role, an e-mail address and the {@link #TENANT} tenant.
     *
     * @return the user and its generated credential.
     */
    TestUser createUser() {
        final var username = "user-" + UUID.randomUUID();
        final var credential = randomValue();
        final var email = username + "@example.com";
        userAccounts.save(new UserAccount(UUID.randomUUID(), username, passwordEncoder.encode(credential), true,
                List.of("ROLE_USER"), email, true, TENANT));
        return new TestUser(username, credential, email);
    }

    /**
     * Creates a confidential client.
     *
     * @param grantTypes grant types of the client.
     * @param scopes     scopes of the client.
     * @param audiences  audiences of the tokens issued to the client.
     * @return the client and its generated credential.
     */
    TestClient createClient(final List<String> grantTypes, final List<String> scopes, final List<String> audiences) {
        return createClient(grantTypes, scopes, audiences, ClientRegistration.FORMAT_SELF_CONTAINED);
    }

    /**
     * Creates a confidential client whose access tokens have the given format.
     *
     * @param grantTypes        grant types of the client.
     * @param scopes            scopes of the client.
     * @param audiences         audiences of the tokens issued to the client.
     * @param accessTokenFormat format of the access tokens ({@code self-contained} or {@code reference}).
     * @return the client and its generated credential.
     */
    TestClient createClient(final List<String> grantTypes, final List<String> scopes, final List<String> audiences,
                            final String accessTokenFormat) {
        final var clientId = "client-" + UUID.randomUUID();
        final var credential = randomValue();
        clientRegistrations.save(new ClientRegistration(clientId, "Test client", true,
                List.of("client_secret_basic"), grantTypes, List.of(REDIRECT_URI), scopes, true, audiences,
                TOKEN_TTL, REFRESH_TTL, accessTokenFormat, false),
                passwordEncoder.encode(credential));
        return new TestClient(clientId, credential);
    }

    /**
     * Creates a client for the authorization code flow with refresh tokens, whose audiences are the resource server
     * and this server's own API (so its users can change their password), like the seeded clients.
     *
     * @return the client and its generated credential.
     */
    TestClient createCodeClient() {
        return createClient(List.of("authorization_code", "refresh_token"),
                List.of("openid", "profile", "email"), List.of(RESOURCE_SERVER_AUDIENCE, API_AUDIENCE));
    }

    /**
     * Obtains an access token with the client credentials grant.
     *
     * @param client client that requests the token.
     * @param scope  requested scope.
     * @return the access token.
     * @throws Exception if a request cannot be performed.
     */
    String clientCredentialsToken(final TestClient client, final String scope) throws Exception {
        final var body = mockMvc.perform(post(TOKEN_PATH)
                        .header(AUTHORIZATION, basic(client.clientId(), client.credential()))
                        .param(GRANT_TYPE, "client_credentials").param("scope", scope))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return parse(body).get("access_token").asString();
    }

    /**
     * Obtains an access token that carries the {@code admin} scope.
     *
     * @return the access token.
     * @throws Exception if a request cannot be performed.
     */
    String adminToken() throws Exception {
        return clientCredentialsToken(
                createClient(List.of("client_credentials"), List.of("admin"), List.of(API_AUDIENCE)), "admin");
    }

    /**
     * Runs the whole authorization code flow with PKCE: authorize, log in, obtain the code and exchange it.
     *
     * @param user   user that signs in.
     * @param client client that requests the tokens.
     * @return the token endpoint answer.
     * @throws Exception if a request cannot be performed.
     */
    JsonNode authorizationCodeTokens(final TestUser user, final TestClient client) throws Exception {
        final var verifier = randomValue() + randomValue();
        final var authorizeUri = UriComponentsBuilder.fromPath("/oauth2/authorize")
                .queryParam("response_type", "code")
                .queryParam("client_id", client.clientId())
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "openid profile email")
                .queryParam("state", "xyz")
                .queryParam("code_challenge", s256(verifier))
                .queryParam("code_challenge_method", "S256")
                .build().toUriString();

        final var session = new MockHttpSession();
        mockMvc.perform(get(authorizeUri).session(session)).andExpect(status().is3xxRedirection());
        mockMvc.perform(post("/login").session(session).with(csrf())
                        .param("username", user.username()).param("password", user.credential()))
                .andExpect(status().is3xxRedirection());
        final var authorized = mockMvc.perform(get(authorizeUri).session(session))
                .andExpect(status().is3xxRedirection()).andReturn();
        final var code = UriComponentsBuilder.fromUriString(authorized.getResponse().getRedirectedUrl()).build()
                .getQueryParams().getFirst("code");
        assertNotNull(code);

        final var body = mockMvc.perform(post(TOKEN_PATH)
                        .header(AUTHORIZATION, basic(client.clientId(), client.credential()))
                        .param(GRANT_TYPE, "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("code_verifier", verifier))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        return parse(body);
    }

    /**
     * Computes the S256 PKCE code challenge of a verifier.
     *
     * @param verifier code verifier.
     * @return the code challenge.
     * @throws NoSuchAlgorithmException if SHA-256 is not available.
     */
    private static String s256(final String verifier) throws NoSuchAlgorithmException {
        final var digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    /**
     * A generated user.
     *
     * @param username   name of the user.
     * @param credential generated credential of the user.
     * @param email      e-mail address of the user.
     */
    record TestUser(String username, String credential, String email) {

        @Override
        public String toString() {
            return "TestUser[username=" + username + "]";
        }
    }

    /**
     * A generated confidential client.
     *
     * @param clientId   identifier of the client.
     * @param credential generated credential of the client.
     */
    record TestClient(String clientId, String credential) {

        @Override
        public String toString() {
            return "TestClient[clientId=" + clientId + "]";
        }
    }
}
