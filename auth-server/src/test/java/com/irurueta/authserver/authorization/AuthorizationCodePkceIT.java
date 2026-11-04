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

import static org.assertj.core.api.Assertions.assertThat;
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
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Full authorization code + PKCE round trip against the real application and a PostgreSQL container:
 * authorize, log in, obtain the code, exchange it with the code verifier and validate the issued tokens
 * against the published JWK set.
 */
@PostgresIT(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class AuthorizationCodePkceIT {

    private static final String REDIRECT_URI = "http://127.0.0.1:8080/callback";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegisteredClientRepository clients;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @LocalServerPort
    private int port;

    @Test
    void authorizationCodeFlowWithPkce_issuesTokensValidAgainstJwks() throws Exception {
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
                .queryParam("redirect_uri", REDIRECT_URI)
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
        final MvcResult authorized = mockMvc.perform(get(authorizeUri).session(session))
                .andExpect(status().is3xxRedirection()).andReturn();
        final var location = UriComponentsBuilder.fromUriString(
                authorized.getResponse().getRedirectedUrl()).build();
        assertThat(location.toUriString()).startsWith(REDIRECT_URI);
        assertThat(location.getQueryParams().getFirst("state")).isEqualTo("xyz");
        final var code = location.getQueryParams().getFirst("code");
        assertThat(code).isNotBlank();

        // 4. exchange the code with the code verifier
        final var basic = Base64.getEncoder().encodeToString(
                (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));
        final var tokenResponse = mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", "Basic " + basic)
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("code_verifier", verifier))
                .andExpect(status().isOk()).andReturn().getResponse().getContentAsString();
        final JsonNode tokens = JsonMapper.builder().build().readTree(tokenResponse);

        // 5. both tokens validate against the published JWK set
        final var decoder = NimbusJwtDecoder.withJwkSetUri("http://localhost:" + port + "/oauth2/jwks").build();
        final var accessToken = decoder.decode(tokens.get("access_token").asString());
        final var idToken = decoder.decode(tokens.get("id_token").asString());
        assertThat(accessToken.getSubject()).isEqualTo(username);
        assertThat(idToken.getSubject()).isEqualTo(username);
        assertThat(idToken.getAudience()).containsExactly(clientId);
        assertThat(idToken.getClaimAsString("nonce")).isEqualTo("n-0S6_WzA2Mj");
        assertThat(idToken.getIssuer()).hasToString("http://localhost:9000");
    }

    @Test
    void tokenRequest_withUnknownCode_isRejected() throws Exception {
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
        final var basic = Base64.getEncoder().encodeToString(
                (clientId + ":" + clientSecret).getBytes(StandardCharsets.UTF_8));

        mockMvc.perform(post("/oauth2/token")
                        .header("Authorization", "Basic " + basic)
                        .param("grant_type", "authorization_code")
                        .param("code", "not-a-real-code")
                        .param("redirect_uri", REDIRECT_URI)
                        .param("code_verifier", randomValue()))
                .andExpect(status().isBadRequest());
    }

    private static String randomValue() {
        final var bytes = new byte[32];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static String s256(final String verifier) throws NoSuchAlgorithmException {
        final var digest = MessageDigest.getInstance("SHA-256")
                .digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}
