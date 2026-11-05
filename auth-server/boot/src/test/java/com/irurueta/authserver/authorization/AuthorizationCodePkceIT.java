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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.testsupport.PostgresIT;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.json.JsonMapper;

/**
 * Full authorization code + PKCE round trip against the real application and a PostgreSQL container:
 * authorize, log in, obtain the code, exchange it with the code verifier and validate the issued tokens
 * against the published JWK set.
 */
@PostgresIT(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class AuthorizationCodePkceIT {

    /** Redirect URI of the test client. */
    private static final String REDIRECT_URI = "http://127.0.0.1:8080/callback";

    /** Number of random bytes of generated values. */
    private static final int RANDOM_BYTES = 32;

    /** Name of the request header that carries the client credentials. */
    private static final String AUTHORIZATION = "Authorization";

    /** Name of the token request parameter that carries the grant type. */
    private static final String GRANT_TYPE = "grant_type";

    /** Name of the token request parameter that carries the authorization code. */
    private static final String CODE = "code";

    /** Name of the token request parameter that carries the redirect URI. */
    private static final String REDIRECT_URI_PARAM = "redirect_uri";

    /** Name of the token request parameter that carries the code verifier. */
    private static final String CODE_VERIFIER = "code_verifier";

    /** Path of the token endpoint. */
    private static final String TOKEN_PATH = "/oauth2/token";

    /** MockMvc bound to the application context. */
    @Autowired
    private MockMvc mockMvc;

    /** Repository where the test client is stored. */
    @Autowired
    private RegisteredClientRepository clients;

    /** JDBC template used to insert the test user. */
    @Autowired
    private JdbcTemplate jdbcTemplate;

    /** Encoder of the application, used for the generated credentials. */
    @Autowired
    private PasswordEncoder passwordEncoder;

    /** Port the application listens on. */
    @LocalServerPort
    private int port;

    /**
     * Verifies that the whole flow issues an access token and an ID token that validate against the JWK set.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void authorizationCodeFlowWithPkce_whenCredentialsAreValid_issuesTokensValidAgainstJwks() throws Exception {
        // all test credentials are generated here and never stored anywhere else
        final var username = "user-" + UUID.randomUUID();
        final var password = randomValue();
        final var clientId = "client-" + UUID.randomUUID();
        final var clientSecret = randomValue();
        final var verifier = randomValue() + randomValue();
        final var challenge = s256(verifier);

        final var userId = UUID.randomUUID();
        jdbcTemplate.update("INSERT INTO users (id, username, enabled) VALUES (?, ?, true)", userId, username);
        jdbcTemplate.update("INSERT INTO user_passwords (user_id, encoded_password) VALUES (?, ?)",
                userId, passwordEncoder.encode(password));
        jdbcTemplate.update("INSERT INTO user_authorities (user_id, authority) VALUES (?, 'ROLE_USER')", userId);

        clients.save(RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret(passwordEncoder.encode(clientSecret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(REDIRECT_URI)
                .scope(OidcScopes.OPENID)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true).requireAuthorizationConsent(false).build())
                .build());

        final var authorizeUri = UriComponentsBuilder.fromPath("/oauth2/authorize")
                .queryParam("response_type", "code")
                .queryParam("client_id", clientId)
                .queryParam(REDIRECT_URI_PARAM, REDIRECT_URI)
                .queryParam("scope", "openid")
                .queryParam("state", "xyz")
                .queryParam("nonce", "n-0S6_WzA2Mj")
                .queryParam("code_challenge", challenge)
                .queryParam("code_challenge_method", "S256")
                .build().toUriString();

        // 1. unauthenticated authorization request is sent to the login page
        final var session = new MockHttpSession();
        mockMvc.perform(get(authorizeUri).session(session))
                .andExpect(status().is3xxRedirection());

        // 2. log in with the generated user
        mockMvc.perform(post("/login").session(session).with(csrf())
                        .param("username", username).param("password", password))
                .andExpect(status().is3xxRedirection());

        // 3. the authorization request is now answered with a redirect carrying the code
        final var authorized = mockMvc.perform(get(authorizeUri).session(session))
                .andExpect(status().is3xxRedirection()).andReturn();
        final var location = UriComponentsBuilder.fromUriString(
                authorized.getResponse().getRedirectedUrl()).build();
        assertTrue(location.toUriString().startsWith(REDIRECT_URI));
        assertEquals("xyz", location.getQueryParams().getFirst("state"));
        final var code = location.getQueryParams().getFirst(CODE);
        assertNotNull(code);

        // 4. exchange the code with the code verifier
        final var tokenResponse = mockMvc.perform(post(TOKEN_PATH)
                        .header(AUTHORIZATION, basic(clientId, clientSecret))
                        .param(GRANT_TYPE, "authorization_code")
                        .param(CODE, code)
                        .param(REDIRECT_URI_PARAM, REDIRECT_URI)
                        .param(CODE_VERIFIER, verifier))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        final var tokens = JsonMapper.builder().build().readTree(tokenResponse);

        // 5. both tokens validate against the published JWK set
        final var decoder = NimbusJwtDecoder.withJwkSetUri("http://localhost:" + port + "/oauth2/jwks").build();
        final var accessToken = decoder.decode(tokens.get("access_token").asString());
        final var idToken = decoder.decode(tokens.get("id_token").asString());
        assertEquals(username, accessToken.getSubject());
        assertEquals(username, idToken.getSubject());
        assertEquals(List.of(clientId), idToken.getAudience());
        assertEquals("n-0S6_WzA2Mj", idToken.getClaimAsString("nonce"));
        assertEquals("http://localhost:9000", idToken.getIssuer().toString());
    }

    /**
     * Verifies that a token request with an unknown authorization code is rejected.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void tokenRequest_whenCodeIsUnknown_isRejected() throws Exception {
        final var clientId = "client-" + UUID.randomUUID();
        final var clientSecret = randomValue();
        clients.save(RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret(passwordEncoder.encode(clientSecret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(REDIRECT_URI)
                .scope(OidcScopes.OPENID)
                .build());

        mockMvc.perform(post(TOKEN_PATH)
                        .header(AUTHORIZATION, basic(clientId, clientSecret))
                        .param(GRANT_TYPE, "authorization_code")
                        .param(CODE, "not-a-real-code")
                        .param(REDIRECT_URI_PARAM, REDIRECT_URI)
                        .param(CODE_VERIFIER, randomValue()))
                .andExpect(status().isBadRequest());
    }

    /**
     * Builds the value of a basic authentication header.
     *
     * @param clientId     identifier of the client.
     * @param clientSecret secret of the client.
     * @return the header value.
     */
    private static String basic(final String clientId, final String clientSecret) {
        return "Basic " + Base64.getEncoder().encodeToString(
                (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Generates a random URL-safe value.
     *
     * @return the value.
     */
    private static String randomValue() {
        final var bytes = new byte[RANDOM_BYTES];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Computes the S256 PKCE code challenge of a verifier.
     *
     * @param verifier code verifier.
     * @return the code challenge.
     * @throws NoSuchAlgorithmException if SHA-256 is not available.
     */
    private static String s256(final String verifier) throws NoSuchAlgorithmException {
        final var digest = MessageDigest.getInstance("SHA-256")
                .digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}
