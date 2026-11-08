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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.irurueta.authserver.authorization.AuthServerFixtures.TestClient;
import com.irurueta.authserver.authorization.api.web.tokens.JwtClaimsContributor;
import com.irurueta.authserver.authorization.application.clients.DefaultClientDefinitions;
import com.irurueta.authserver.authorization.domain.clients.ClientRegistrationRepository;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import com.irurueta.authserver.testsupport.PostgresIT;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimNames;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import tools.jackson.databind.JsonNode;

/**
 * Checks the token exchange (RFC 8693) of the real application: a user token exchanged by a confidential client
 * together with an actor token, the audience honoured by
 * {@link com.irurueta.authserver.authorization.api.web.exchange.TokenExchangeAudienceContributor}, and the refusals
 * (client without the grant, token not issued by this server, {@code may_act} that excludes the actor).
 */
@PostgresIT
@AutoConfigureMockMvc
@Import(TokenExchangeIT.MayActConfiguration.class)
class TokenExchangeIT {

    /** URN of the access token type. */
    private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

    /** Name of the answer field that carries the access token. */
    private static final String ACCESS_TOKEN = "access_token";

    /** Name of the answer field that carries the error code. */
    private static final String ERROR = "error";

    /** Scopes of the exchanging client, which include those of the user token. */
    private static final List<String> EXCHANGE_SCOPES = List.of("openid", "profile", "email");

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

    /** Registry of the {@code may_act} claims added to the user tokens of some clients. */
    @Autowired
    private Map<String, Map<String, Object>> mayActClaims;

    /** Fixtures of the test. */
    private AuthServerFixtures fixtures;

    /** Creates the fixtures. */
    @BeforeEach
    void setUp() {
        fixtures = new AuthServerFixtures(mockMvc, passwordEncoder, userAccounts, clientRegistrations);
    }

    /**
     * The exchange of a user token with an actor token answers an access token of the user, acted by the client, for
     * the requested audience only.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void tokenExchange_whenSubjectAndActorTokensAreValid_issuesTokenOfTheUserActedByTheClient() throws Exception {
        final var user = fixtures.createUser();
        final var subject = fixtures.authorizationCodeTokens(user, fixtures.createCodeClient())
                .get(ACCESS_TOKEN).asString();
        final var client = createExchangeClient(true);
        final var actor = fixtures.clientCredentialsToken(client, "profile");

        final var answer = AuthServerFixtures.parse(exchange(client, subject, actor,
                AuthServerFixtures.RESOURCE_SERVER_AUDIENCE).andExpect(status().isOk()).andReturn().getResponse()
                .getContentAsString());

        assertEquals(ACCESS_TOKEN_TYPE, answer.get("issued_token_type").asString());
        final var claims = AuthServerFixtures.claimsOf(answer.get(ACCESS_TOKEN).asString());
        assertEquals(user.username(), claims.get(OAuth2TokenClaimNames.SUB).asString());
        assertEquals(client.clientId(), claims.get("act").get(OAuth2TokenClaimNames.SUB).asString());
        assertEquals(List.of(AuthServerFixtures.RESOURCE_SERVER_AUDIENCE),
                audiencesOf(claims.get(OAuth2TokenClaimNames.AUD)));
    }

    /**
     * A client that was not registered with the token exchange grant is refused.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void tokenExchange_whenClientHasNoExchangeGrant_isRefused() throws Exception {
        final var user = fixtures.createUser();
        final var subject = fixtures.authorizationCodeTokens(user, fixtures.createCodeClient())
                .get(ACCESS_TOKEN).asString();
        final var client = createExchangeClient(false);
        final var actor = fixtures.clientCredentialsToken(client, "profile");

        final var answer = refused(client, subject, actor);

        assertEquals("unauthorized_client", answer.get(ERROR).asString());
    }

    /**
     * A subject token this server did not issue is refused.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void tokenExchange_whenSubjectTokenIsForeign_isRefused() throws Exception {
        final var client = createExchangeClient(true);
        final var actor = fixtures.clientCredentialsToken(client, "profile");

        final var answer = refused(client, AuthServerFixtures.randomValue(), actor);

        assertEquals("invalid_grant", answer.get(ERROR).asString());
    }

    /**
     * When the subject token names who may act and the actor is somebody else, the exchange is refused.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void tokenExchange_whenMayActExcludesTheActor_isRefused() throws Exception {
        final var user = fixtures.createUser();
        final var codeClient = fixtures.createCodeClient();
        mayActClaims.put(codeClient.clientId(), Map.of(OAuth2TokenClaimNames.SUB, "somebody-else"));
        final var subject = fixtures.authorizationCodeTokens(user, codeClient).get(ACCESS_TOKEN).asString();
        assertTrue(AuthServerFixtures.claimsOf(subject).has("may_act"));
        final var client = createExchangeClient(true);
        final var actor = fixtures.clientCredentialsToken(client, "profile");

        final var answer = refused(client, subject, actor);

        assertEquals("invalid_grant", answer.get(ERROR).asString());
    }

    /**
     * When the subject token names the actor that exchanges it, the exchange succeeds.
     *
     * @throws Exception if a request cannot be performed.
     */
    @Test
    void tokenExchange_whenMayActNamesTheActor_issuesToken() throws Exception {
        final var user = fixtures.createUser();
        final var codeClient = fixtures.createCodeClient();
        final var client = createExchangeClient(true);
        final var actor = fixtures.clientCredentialsToken(client, "profile");
        final var actorClaims = AuthServerFixtures.claimsOf(actor);
        final var mayAct = new HashMap<String, Object>();
        mayAct.put(OAuth2TokenClaimNames.ISS, issuerOf(actorClaims));
        mayAct.put(OAuth2TokenClaimNames.SUB, client.clientId());
        mayActClaims.put(codeClient.clientId(), mayAct);
        final var subject = fixtures.authorizationCodeTokens(user, codeClient).get(ACCESS_TOKEN).asString();

        exchange(client, subject, actor, AuthServerFixtures.RESOURCE_SERVER_AUDIENCE).andExpect(status().isOk());
    }

    /**
     * Reads the issuer of a token as the framework compares it: the stored claims of an issued token hold {@code iss}
     * as a {@link URL}, and a {@code may_act} claim must carry the same type to match.
     *
     * @param claims the claims of the token.
     * @return the issuer.
     * @throws MalformedURLException if the issuer is not a URL.
     */
    private static URL issuerOf(final JsonNode claims) throws MalformedURLException {
        return URI.create(claims.get(OAuth2TokenClaimNames.ISS).asString()).toURL();
    }

    /**
     * Reads an {@code aud} claim, which a JWT serializes as a string when it has one value and as an array otherwise.
     *
     * @param aud the claim.
     * @return its values.
     */
    private static List<String> audiencesOf(final JsonNode aud) {
        if (aud.isArray()) {
            return aud.values().stream().map(JsonNode::asString).toList();
        }
        return List.of(aud.asString());
    }

    /**
     * Creates a confidential client for the exchange.
     *
     * @param withExchangeGrant whether it has the token exchange grant.
     * @return the client.
     */
    private TestClient createExchangeClient(final boolean withExchangeGrant) {
        final var grants = withExchangeGrant
                ? List.of("client_credentials", DefaultClientDefinitions.TOKEN_EXCHANGE_GRANT)
                : List.of("client_credentials");
        return fixtures.createClient(grants, EXCHANGE_SCOPES,
                List.of(AuthServerFixtures.RESOURCE_SERVER_AUDIENCE, AuthServerFixtures.API_AUDIENCE));
    }

    /**
     * Performs a token exchange request.
     *
     * @param client   the exchanging client.
     * @param subject  the subject token.
     * @param actor    the actor token.
     * @param audience the requested audience.
     * @return the result actions.
     * @throws Exception if the request cannot be performed.
     */
    private ResultActions exchange(final TestClient client, final String subject, final String actor,
                                   final String audience)
            throws Exception {
        return mockMvc.perform(post(AuthServerFixtures.TOKEN_PATH)
                .header(AuthServerFixtures.AUTHORIZATION,
                        AuthServerFixtures.basic(client.clientId(), client.credential()))
                .param(AuthServerFixtures.GRANT_TYPE, DefaultClientDefinitions.TOKEN_EXCHANGE_GRANT)
                .param("subject_token", subject).param("subject_token_type", ACCESS_TOKEN_TYPE)
                .param("actor_token", actor).param("actor_token_type", ACCESS_TOKEN_TYPE)
                .param("audience", audience));
    }

    /**
     * Performs a token exchange request that must be answered with a {@code 400}.
     *
     * @param client  the exchanging client.
     * @param subject the subject token.
     * @param actor   the actor token.
     * @return the error answer.
     * @throws Exception if the request cannot be performed.
     */
    private JsonNode refused(final TestClient client, final String subject, final String actor) throws Exception {
        return AuthServerFixtures.parse(exchange(client, subject, actor, AuthServerFixtures.RESOURCE_SERVER_AUDIENCE)
                .andExpect(status().isBadRequest()).andReturn().getResponse().getContentAsString());
    }

    /**
     * Adds a {@code may_act} claim to the access tokens of the clients registered in the test. It stays
     * package-private: the test class's own {@code @Import} cannot name a private nested class.
     */
    @TestConfiguration(proxyBeanMethods = false)
    static class MayActConfiguration {

        /**
         * Claims by client identifier.
         *
         * @return the registry.
         */
        @Bean
        Map<String, Map<String, Object>> mayActClaims() {
            return new ConcurrentHashMap<>();
        }

        /**
         * Contributes the registered claim to the access tokens of its client.
         *
         * @param registry the claims by client identifier.
         * @return the contributor.
         */
        @Bean
        @Order(130)
        JwtClaimsContributor mayActContributor(final Map<String, Map<String, Object>> registry) {
            return (context, claims) -> {
                final var mayAct = registry.get(context.getRegisteredClient().getClientId());
                if (mayAct != null && OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                    claims.put("may_act", new HashMap<>(mayAct));
                }
            };
        }
    }
}
