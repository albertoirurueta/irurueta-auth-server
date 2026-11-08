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

package com.irurueta.authserver.authorization.api.web.exchange;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.irurueta.authserver.authorization.api.web.tokens.IssuedTokenClaims;
import com.irurueta.authserver.authorization.application.clients.DefaultClientDefinitions;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenExchangeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimNames;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimsSet;

/**
 * Unit tests of {@link TokenExchangeAudienceContributor}.
 */
class TokenExchangeAudienceContributorTest {

    /** Audience of the resource server. */
    private static final String RESOURCE_SERVER = "resource-server";

    /** Audience of the API of the server. */
    private static final String API = "auth-server";

    /** Audience that the client may not have. */
    private static final String FOREIGN = "somebody-else";

    /** Token type URN of an access token. */
    private static final String ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token";

    /** Expected order of the contributor. */
    private static final int EXPECTED_ORDER = 120;

    /** Subject under test. */
    private final TokenExchangeAudienceContributor contributor = new TokenExchangeAudienceContributor();

    /**
     * The order places the contributor after the multi-factor and identity provider ones.
     */
    @Test
    void order_always_is120() {
        assertEquals(EXPECTED_ORDER, TokenExchangeAudienceContributor.ORDER);
        assertEquals(TokenExchangeAudienceContributor.ORDER,
                TokenExchangeAudienceContributor.class.getAnnotation(Order.class).value());
    }

    /**
     * The exchange grant constant is the RFC 8693 URN.
     */
    @Test
    void tokenExchangeGrant_always_isTheGrantTypeUrn() {
        assertEquals(AuthorizationGrantType.TOKEN_EXCHANGE.getValue(), DefaultClientDefinitions.TOKEN_EXCHANGE_GRANT);
    }

    /**
     * Only the requested audiences the client may have are kept.
     */
    @Test
    void contribute_whenRequestedAudiencesAreAllowed_keepsOnlyThoseRequested() {
        final var claims = claimsWithAudiences(RESOURCE_SERVER, API);

        contributor.contribute(contextOf(AuthorizationGrantType.TOKEN_EXCHANGE, OAuth2TokenType.ACCESS_TOKEN,
                Set.of(RESOURCE_SERVER, FOREIGN)), claims);

        assertEquals(List.of(RESOURCE_SERVER), claims.get(OAuth2TokenClaimNames.AUD));
    }

    /**
     * A request whose audiences the client may not have is refused with invalid_target and the claims stay untouched.
     */
    @Test
    void contribute_whenNoRequestedAudienceIsAllowed_throwsInvalidTarget() {
        final var claims = claimsWithAudiences(RESOURCE_SERVER, API);
        final var context = contextOf(AuthorizationGrantType.TOKEN_EXCHANGE, OAuth2TokenType.ACCESS_TOKEN,
                Set.of(FOREIGN));

        final var error = assertThrows(OAuth2AuthenticationException.class,
                () -> contributor.contribute(context, claims));

        assertEquals(TokenExchangeAudienceContributor.INVALID_TARGET, error.getError().getErrorCode());
        assertEquals(List.of(RESOURCE_SERVER, API), claims.get(OAuth2TokenClaimNames.AUD));
    }

    /**
     * When only some requested audiences are allowed, the allowed ones are granted and the others dropped.
     */
    @Test
    void contribute_whenSomeRequestedAudiencesAreAllowed_grantsOnlyThose() {
        final var claims = claimsWithAudiences(RESOURCE_SERVER, API);

        contributor.contribute(contextOf(AuthorizationGrantType.TOKEN_EXCHANGE, OAuth2TokenType.ACCESS_TOKEN,
                new LinkedHashSet<>(List.of(API, FOREIGN))), claims);

        assertEquals(List.of(API), claims.get(OAuth2TokenClaimNames.AUD));
    }

    /**
     * A request with no audience leaves the audiences of the client.
     */
    @Test
    void contribute_whenNoAudienceIsRequested_keepsTheAudiencesOfTheClient() {
        final var claims = claimsWithAudiences(RESOURCE_SERVER, API);

        contributor.contribute(contextOf(AuthorizationGrantType.TOKEN_EXCHANGE, OAuth2TokenType.ACCESS_TOKEN,
                Set.of()), claims);

        assertEquals(List.of(RESOURCE_SERVER, API), claims.get(OAuth2TokenClaimNames.AUD));
    }

    /**
     * Another grant type is not touched.
     */
    @Test
    void contribute_whenGrantIsNotATokenExchange_doesNothing() {
        final var claims = claimsWithAudiences(RESOURCE_SERVER, API);

        contributor.contribute(contextOf(AuthorizationGrantType.CLIENT_CREDENTIALS, OAuth2TokenType.ACCESS_TOKEN,
                Set.of(RESOURCE_SERVER)), claims);

        assertEquals(List.of(RESOURCE_SERVER, API), claims.get(OAuth2TokenClaimNames.AUD));
    }

    /**
     * A token that is not an access token is not touched.
     */
    @Test
    void contribute_whenTokenIsNotAnAccessToken_doesNothing() {
        final var claims = claimsWithAudiences(RESOURCE_SERVER, API);

        contributor.contribute(contextOf(AuthorizationGrantType.TOKEN_EXCHANGE, OAuth2TokenType.REFRESH_TOKEN,
                Set.of(RESOURCE_SERVER)), claims);

        assertEquals(List.of(RESOURCE_SERVER, API), claims.get(OAuth2TokenClaimNames.AUD));
    }

    /**
     * A client without the audiences setting may have no requested audience: the request is refused.
     */
    @Test
    void contribute_whenClientHasNoAudiencesSetting_throwsInvalidTarget() {
        final var claims = new HashMap<String, Object>();
        final var client = clientBuilder().build();
        final var context = OAuth2TokenClaimsContext.with(OAuth2TokenClaimsSet.builder().subject("user"))
                .registeredClient(client).principal(new TestingAuthenticationToken("user", "n"))
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .authorizationGrant(exchange(client, Set.of(RESOURCE_SERVER)))
                .tokenType(OAuth2TokenType.ACCESS_TOKEN).build();

        final var error = assertThrows(OAuth2AuthenticationException.class,
                () -> contributor.contribute(context, claims));

        assertEquals(TokenExchangeAudienceContributor.INVALID_TARGET, error.getError().getErrorCode());
        assertFalse(claims.containsKey(OAuth2TokenClaimNames.AUD));
    }

    /**
     * The claim is a mutable list, as the authorization store only deserializes allow-listed types.
     */
    @Test
    void contribute_whenAudiencesAreGranted_putsAMutableList() {
        final var claims = claimsWithAudiences(RESOURCE_SERVER, API);

        contributor.contribute(contextOf(AuthorizationGrantType.TOKEN_EXCHANGE, OAuth2TokenType.ACCESS_TOKEN,
                Set.of(RESOURCE_SERVER)), claims);

        final var audiences = claims.get(OAuth2TokenClaimNames.AUD);
        assertNotNull(audiences);
        assertEquals(ArrayList.class, audiences.getClass());
    }

    /**
     * Builds the claims of an access token that already carry the audiences of the client.
     *
     * @param audiences audiences of the client.
     * @return the mutable claims.
     */
    private static HashMap<String, Object> claimsWithAudiences(final String... audiences) {
        final var claims = new HashMap<String, Object>();
        claims.put(OAuth2TokenClaimNames.AUD, new ArrayList<>(List.of(audiences)));
        return claims;
    }

    /**
     * Builds a client that may exchange tokens and may have the resource server and API audiences.
     *
     * @return the builder.
     */
    private static RegisteredClient.Builder clientBuilder() {
        return RegisteredClient.withId(UUID.randomUUID().toString()).clientId("client")
                .authorizationGrantType(AuthorizationGrantType.TOKEN_EXCHANGE)
                .redirectUri("https://client.example.com/callback");
    }

    /**
     * Builds a token exchange request that asks for the given audiences.
     *
     * @param client    the exchanging client.
     * @param audiences requested audiences.
     * @return the request.
     */
    private static OAuth2TokenExchangeAuthenticationToken exchange(final RegisteredClient client,
                                                                   final Set<String> audiences) {
        return new OAuth2TokenExchangeAuthenticationToken(ACCESS_TOKEN_TYPE, "subject", ACCESS_TOKEN_TYPE,
                new TestingAuthenticationToken(client.getClientId(), "n"), null, null, null,
                new LinkedHashSet<>(audiences), null, null);
    }

    /**
     * Builds the context of a token of an exchanging client that may have the resource server and API audiences.
     *
     * @param grantType grant type of the context.
     * @param tokenType type of the token.
     * @param requested audiences requested in the exchange.
     * @return the context.
     */
    private static OAuth2TokenClaimsContext contextOf(final AuthorizationGrantType grantType,
                                                      final OAuth2TokenType tokenType, final Set<String> requested) {
        final var client = clientBuilder().clientSettings(ClientSettings.builder()
                .setting(IssuedTokenClaims.AUDIENCES_SETTING, List.of(RESOURCE_SERVER, API)).build()).build();
        return OAuth2TokenClaimsContext.with(OAuth2TokenClaimsSet.builder().subject("user"))
                .registeredClient(client).principal(new TestingAuthenticationToken("user", "n"))
                .authorizationGrantType(grantType).authorizationGrant(exchange(client, requested))
                .tokenType(tokenType).build();
    }
}
