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

package com.irurueta.authserver.authorization.api.web.tokens;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.password.FindUserAccountUseCase;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;

/**
 * Unit tests of {@link IssuedTokenClaims}, applied to the claims of a JWT encoding context.
 */
class IssuedTokenClaimsTest {

    /** Username of the test user. */
    private static final String USERNAME = "alice";

    /** Tenant of the test user. */
    private static final String TENANT = "acme";

    /** Client identifier. */
    private static final String CLIENT_ID = "client";

    /** Redirect URI of the client. */
    private static final String REDIRECT_URI = "https://client.example.com/callback";

    /** Audience configured in the client. */
    private static final String AUDIENCE = "documents";

    /** Role of the test user. */
    private static final String ROLE_USER = "ROLE_USER";

    /** Role of the test user. */
    private static final String ROLE_ADMIN = "ROLE_ADMIN";

    /** Claim added by the contributor in the tests. */
    private static final String CONTRIBUTED = "amr";

    /** Finds accounts. */
    private FindUserAccountUseCase findUserAccountUseCase;

    /** Contributor of additional claims. */
    private JwtClaimsContributor contributor;

    /** Subject under test. */
    private IssuedTokenClaims issuedTokenClaims;

    /**
     * Creates the subject with a mocked use case and contributor.
     */
    @BeforeEach
    void setUp() {
        findUserAccountUseCase = mock(FindUserAccountUseCase.class);
        contributor = mock(JwtClaimsContributor.class);
        issuedTokenClaims = new IssuedTokenClaims(findUserAccountUseCase, List.of(contributor));
    }

    /**
     * An authorization code access token gets roles, tenant and the audiences of the client.
     */
    @Test
    void apply_whenAccessTokenOfUser_addsRolesTenantAndAudience() {
        final var account = new UserAccount(UUID.randomUUID(), USERNAME, "x", true, List.of(ROLE_USER), null,
                false, TENANT);
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.of(account));
        final var context = context(OAuth2TokenType.ACCESS_TOKEN, AuthorizationGrantType.AUTHORIZATION_CODE,
                List.of(AUDIENCE));

        apply(context);

        final var claims = build(context);
        assertEquals(List.of(ROLE_ADMIN, ROLE_USER), claims.getClaim(IssuedTokenClaims.ROLES_CLAIM));
        assertEquals(TENANT, claims.getClaim(IssuedTokenClaims.TENANT_CLAIM));
        assertEquals(List.of(AUDIENCE), claims.getAudience());
        verify(contributor).contribute(eq(context), anyMap());
    }

    /**
     * Factor authorities record how the user signed in; they never become roles, and the roles list is mutable so
     * the authorization store can read it back.
     */
    @Test
    void apply_whenPrincipalHasFactorAuthorities_leavesThemOutOfTheRoles() {
        final Authentication principal = new TestingAuthenticationToken(USERNAME, null,
                List.of(FactorGrantedAuthority.fromAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY),
                        new SimpleGrantedAuthority(ROLE_USER)));
        final var context = context(OAuth2TokenType.ACCESS_TOKEN, AuthorizationGrantType.AUTHORIZATION_CODE,
                List.of(AUDIENCE), principal);

        apply(context);

        final var roles = build(context).<List<String>>getClaim(IssuedTokenClaims.ROLES_CLAIM);
        assertEquals(List.of(ROLE_USER), roles);
        assertEquals(ArrayList.class, roles.getClass());
    }

    /**
     * A user without account gets roles but no tenant.
     */
    @Test
    void apply_whenAccountIsMissing_omitsTenant() {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.empty());
        final var context = context(OAuth2TokenType.ACCESS_TOKEN, AuthorizationGrantType.AUTHORIZATION_CODE,
                List.of());

        apply(context);

        final var claims = build(context);
        assertNull(claims.getClaim(IssuedTokenClaims.TENANT_CLAIM));
        assertNull(claims.getAudience());
    }

    /**
     * The client credentials grant has no user: no roles, no tenant and no account lookup.
     */
    @Test
    void apply_whenClientCredentials_skipsUserClaims() {
        final var context = context(OAuth2TokenType.ACCESS_TOKEN, AuthorizationGrantType.CLIENT_CREDENTIALS,
                List.of(AUDIENCE));

        apply(context);

        final var claims = build(context);
        assertFalse(claims.hasClaim(IssuedTokenClaims.ROLES_CLAIM));
        assertEquals(List.of(AUDIENCE), claims.getAudience());
        verifyNoInteractions(findUserAccountUseCase);
    }

    /**
     * An ID token gets no roles, tenant or access-token audience, but the contributors still run for it, so a
     * feature can add an ID-token claim such as {@code amr}.
     */
    @Test
    void apply_whenIdToken_runsTheContributorsOnly() {
        final var context = context(IssuedTokenClaims.ID_TOKEN, AuthorizationGrantType.AUTHORIZATION_CODE,
                List.of(AUDIENCE));
        doAnswer(invocation -> invocation.<Map<String, Object>>getArgument(1).put(CONTRIBUTED, "pwd"))
                .when(contributor).contribute(eq(context), anyMap());

        apply(context);

        final var claims = build(context);
        assertEquals("pwd", claims.getClaim(CONTRIBUTED));
        assertFalse(claims.hasClaim(IssuedTokenClaims.ROLES_CLAIM));
        assertFalse(claims.hasClaim(IssuedTokenClaims.TENANT_CLAIM));
        assertNull(claims.getAudience());
        verifyNoInteractions(findUserAccountUseCase);
    }

    /**
     * An access token gets the contributed claims too, after the built-in ones.
     */
    @Test
    void apply_whenAccessToken_addsTheContributedClaims() {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.empty());
        final var context = context(OAuth2TokenType.ACCESS_TOKEN, AuthorizationGrantType.AUTHORIZATION_CODE,
                List.of(AUDIENCE));
        doAnswer(invocation -> invocation.<Map<String, Object>>getArgument(1).put(CONTRIBUTED, "pwd"))
                .when(contributor).contribute(eq(context), anyMap());

        apply(context);

        assertEquals("pwd", build(context).getClaim(CONTRIBUTED));
    }

    /**
     * Any other token is left untouched, and no contributor runs for it.
     */
    @Test
    void apply_whenNeitherAccessNorIdToken_doesNothing() {
        final var context = context(OAuth2TokenType.REFRESH_TOKEN, AuthorizationGrantType.AUTHORIZATION_CODE,
                List.of(AUDIENCE));

        apply(context);

        verifyNoInteractions(findUserAccountUseCase, contributor);
        assertFalse(build(context).hasClaim(IssuedTokenClaims.ROLES_CLAIM));
    }

    /**
     * Applies the claims to the claims of a context, as the customizers do.
     *
     * @param context the context.
     */
    private void apply(final JwtEncodingContext context) {
        context.getClaims().claims(claims -> issuedTokenClaims.apply(context, claims));
    }

    /**
     * Builds the claims of a context.
     *
     * @param context the context.
     * @return the claims.
     */
    private static JwtClaimsSet build(final JwtEncodingContext context) {
        return context.getClaims().build();
    }

    /**
     * Creates an encoding context.
     *
     * @param tokenType token type.
     * @param grantType grant type.
     * @param audiences audiences configured in the client; empty to leave the setting absent.
     * @return the context.
     */
    private static JwtEncodingContext context(
            final OAuth2TokenType tokenType, final AuthorizationGrantType grantType, final List<String> audiences) {
        return context(tokenType, grantType, audiences,
                new TestingAuthenticationToken(USERNAME, null, ROLE_USER, ROLE_ADMIN));
    }

    /**
     * Creates an encoding context.
     *
     * @param tokenType token type.
     * @param grantType grant type.
     * @param audiences audiences configured in the client; empty to leave the setting absent.
     * @param principal authenticated principal of the grant.
     * @return the context.
     */
    private static JwtEncodingContext context(
            final OAuth2TokenType tokenType, final AuthorizationGrantType grantType, final List<String> audiences,
            final Authentication principal) {
        final var settings = ClientSettings.builder();
        if (!audiences.isEmpty()) {
            settings.setting(IssuedTokenClaims.AUDIENCES_SETTING, audiences);
        }
        final var client = RegisteredClient.withId(UUID.randomUUID().toString()).clientId(CLIENT_ID)
                .authorizationGrantType(grantType).redirectUri(REDIRECT_URI).clientSettings(settings.build()).build();
        final var header = JwsHeader.with(SignatureAlgorithm.RS256);
        final var claims = JwtClaimsSet.builder().subject(USERNAME);
        return JwtEncodingContext.with(header, claims).registeredClient(client).principal(principal)
                .authorizationGrantType(grantType).tokenType(tokenType).build();
    }
}
