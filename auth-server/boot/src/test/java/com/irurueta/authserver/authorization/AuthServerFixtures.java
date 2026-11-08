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

import com.irurueta.authserver.authorization.application.totp.GenerateRecoveryCodesUseCase;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistration;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.mfa.UserMfaSettingsRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.authorization.domain.totp.SecretGenerator;
import com.irurueta.authserver.authorization.domain.totp.TotpAlgorithm;
import com.irurueta.authserver.authorization.domain.totp.TotpCredential;
import com.irurueta.authserver.authorization.domain.totp.TotpCredentialRepository;
import com.irurueta.authserver.authorization.domain.totp.TotpSecretCipher;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.stream.IntStream;
import java.util.stream.LongStream;
import lombok.RequiredArgsConstructor;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
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
                TOKEN_TTL, REFRESH_TTL, accessTokenFormat, false, List.of(), false, false,
                null, null, null, null, false),
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
        return createCodeClient(List.of());
    }

    /**
     * Creates a client for the authorization code flow that may send the user to the given URIs after an OpenID
     * Connect RP-initiated logout.
     *
     * @param postLogoutRedirectUris the registered post-logout redirect URIs.
     * @return the client and its generated credential.
     */
    TestClient createCodeClient(final List<String> postLogoutRedirectUris) {
        return createCodeClient(postLogoutRedirectUris, false);
    }

    /**
     * Creates a client for the authorization code flow whose users must always present a second factor.
     *
     * @return the client and its generated credential.
     */
    TestClient createMfaCodeClient() {
        return createCodeClient(List.of(), true);
    }

    /**
     * Creates a client for the authorization code flow.
     *
     * @param postLogoutRedirectUris the registered post-logout redirect URIs.
     * @param mfaRequired            whether the client makes multi-factor authentication mandatory.
     * @return the client and its generated credential.
     */
    TestClient createCodeClient(final List<String> postLogoutRedirectUris, final boolean mfaRequired) {
        final var clientId = "client-" + UUID.randomUUID();
        final var credential = randomValue();
        clientRegistrations.save(new ClientRegistration(clientId, "Test client", true,
                List.of("client_secret_basic"), List.of("authorization_code", "refresh_token"),
                List.of(REDIRECT_URI), List.of("openid", "profile", "email"), true,
                List.of(RESOURCE_SERVER_AUDIENCE, API_AUDIENCE), TOKEN_TTL, REFRESH_TTL,
                ClientRegistration.FORMAT_SELF_CONTAINED, false, postLogoutRedirectUris, false, mfaRequired,
                null, null, null, null, false),
                passwordEncoder.encode(credential));
        return new TestClient(clientId, credential);
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
        return authorizationCodeTokens(user, client, new MockHttpSession());
    }

    /**
     * Runs the whole authorization code flow with PKCE in the given browser session, which stays signed in.
     *
     * @param user    user that signs in.
     * @param client  client that requests the tokens.
     * @param session browser session that holds the sign-in.
     * @return the token endpoint answer.
     * @throws Exception if a request cannot be performed.
     */
    JsonNode authorizationCodeTokens(final TestUser user, final TestClient client, final MockHttpSession session)
            throws Exception {
        final var verifier = randomValue() + randomValue();
        final var authorizeUri = authorizeUri(client, verifier, Map.of());

        mockMvc.perform(get(authorizeUri).session(session)).andExpect(status().is3xxRedirection());
        signIn(user, session);
        final var authorized = mockMvc.perform(get(authorizeUri).session(session))
                .andExpect(status().is3xxRedirection()).andReturn();
        return exchangeCode(client, codeOf(authorized), verifier);
    }

    /**
     * Builds the URI of an authorization request with PKCE.
     *
     * @param client   client that requests the code.
     * @param verifier PKCE code verifier.
     * @param extra    additional query parameters (for example {@code acr_values} or {@code max_age}).
     * @return the request URI.
     * @throws NoSuchAlgorithmException if SHA-256 is not available.
     */
    static String authorizeUri(final TestClient client, final String verifier, final Map<String, String> extra)
            throws NoSuchAlgorithmException {
        final var builder = UriComponentsBuilder.fromPath("/oauth2/authorize")
                .queryParam("response_type", "code")
                .queryParam("client_id", client.clientId())
                .queryParam("redirect_uri", REDIRECT_URI)
                .queryParam("scope", "openid profile email")
                .queryParam("state", "xyz")
                .queryParam("code_challenge", s256(verifier))
                .queryParam("code_challenge_method", "S256");
        extra.forEach(builder::queryParam);
        return builder.build().toUriString();
    }

    /**
     * Posts the password login form.
     *
     * @param user    user that signs in.
     * @param session browser session that holds the sign-in.
     * @throws Exception if the request cannot be performed.
     */
    void signIn(final TestUser user, final MockHttpSession session) throws Exception {
        mockMvc.perform(post("/login").session(session).with(csrf())
                        .param("username", user.username()).param("password", user.credential()))
                .andExpect(status().is3xxRedirection());
    }

    /**
     * Reads the authorization code a redirect carries.
     *
     * @param authorized the answer of the authorization endpoint.
     * @return the code.
     */
    static String codeOf(final MvcResult authorized) {
        final var code = UriComponentsBuilder.fromUriString(authorized.getResponse().getRedirectedUrl()).build()
                .getQueryParams().getFirst("code");
        assertNotNull(code);
        return code;
    }

    /**
     * Exchanges an authorization code for the tokens.
     *
     * @param client   client that requests the tokens.
     * @param code     authorization code.
     * @param verifier PKCE code verifier.
     * @return the token endpoint answer.
     * @throws Exception if a request cannot be performed.
     */
    JsonNode exchangeCode(final TestClient client, final String code, final String verifier) throws Exception {
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
     * Reads the claims of a JWT without verifying it (the tests only inspect what the server issued).
     *
     * @param jwt the compact serialization of the token.
     * @return its claims.
     */
    static JsonNode claimsOf(final String jwt) {
        final var payload = jwt.split("\\.")[1];
        return parse(new String(Base64.getUrlDecoder().decode(payload), StandardCharsets.UTF_8));
    }

    /**
     * Creates a user whose authenticator app is enrolled and confirmed, with recovery codes. The secret is generated
     * at runtime and never leaves the test.
     *
     * @param tools collaborators that store the credential and compute codes.
     * @return the user, its identifier and its plain recovery codes.
     */
    EnrolledUser createEnrolledUser(final TotpTools tools) {
        final var user = createUser();
        final var id = userAccounts.findByUsername(user.username()).orElseThrow().id();
        tools.credentials().save(new TotpCredential(id, tools.cipher().encrypt(tools.secrets().generate()), true,
                TotpCredential.NEVER_USED, Instant.now()));
        return new EnrolledUser(user, id, tools.recoveryCodes().execute(id));
    }

    /**
     * Requires multi-factor authentication of a user's account.
     *
     * @param user  the user.
     * @param tools collaborators of the tests.
     */
    void requireMfa(final TestUser user, final TotpTools tools) {
        tools.mfaSettings().setRequired(userAccounts.findByUsername(user.username()).orElseThrow().id(), true);
    }

    /**
     * Computes the S256 PKCE code challenge of a verifier.
     *
     * @param verifier code verifier.
     * @return the code challenge.
     * @throws NoSuchAlgorithmException if SHA-256 is not available.
     */
    static String s256(final String verifier) throws NoSuchAlgorithmException {
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

    /**
     * A user with an enrolled authenticator app.
     *
     * @param user          the user.
     * @param id            identifier of the account.
     * @param recoveryCodes the plain recovery codes, shown to the user once.
     */
    record EnrolledUser(TestUser user, UUID id, List<String> recoveryCodes) {

        @Override
        public String toString() {
            return "EnrolledUser[id=" + id + "]";
        }
    }

    /**
     * Collaborators the tests use to enrol an authenticator app and to compute the codes it would show.
     *
     * @param credentials   port that stores the credentials.
     * @param cipher        cipher of the stored secrets.
     * @param secrets       generator of secrets.
     * @param algorithm     TOTP algorithm of the application.
     * @param recoveryCodes use case that generates recovery codes.
     * @param mfaSettings   port that stores the per-user multi-factor settings.
     */
    record TotpTools(TotpCredentialRepository credentials, TotpSecretCipher cipher, SecretGenerator secrets,
                     TotpAlgorithm algorithm, GenerateRecoveryCodesUseCase recoveryCodes,
                     UserMfaSettingsRepository mfaSettings) {

        /**
         * Computes the code the authenticator app of a user shows at the given step.
         *
         * @param userId identifier of the user.
         * @param step   time step.
         * @return the six-digit code.
         */
        String codeAt(final UUID userId, final long step) {
            return algorithm.generate(cipher.decrypt(credentials.findByUser(userId).orElseThrow().encryptedSecret()),
                    step);
        }

        /**
         * Computes a code for a step relative to the current one.
         *
         * @param userId identifier of the user.
         * @param offset steps from the current one ({@code -1}, {@code 0} or {@code 1} are accepted).
         * @return the six-digit code.
         */
        String codeNow(final UUID userId, final long offset) {
            return codeAt(userId, algorithm.stepAt(Instant.now()) + offset);
        }

        /**
         * Computes a code the algorithm does not accept now, whatever the clock skew.
         *
         * @param userId identifier of the user.
         * @return a six-digit code outside the accepted window.
         */
        String wrongCode(final UUID userId) {
            final var now = algorithm.stepAt(Instant.now());
            final var accepted = LongStream.rangeClosed(now - TotpAlgorithm.WINDOW - 1, now + TotpAlgorithm.WINDOW + 1)
                    .mapToObj(step -> codeAt(userId, step)).toList();
            return IntStream.iterate(0, i -> i + 1)
                    .mapToObj(i -> String.format(Locale.ROOT, "%0" + TotpAlgorithm.DIGITS + "d", i))
                    .filter(candidate -> !accepted.contains(candidate)).findFirst().orElseThrow();
        }
    }
}
