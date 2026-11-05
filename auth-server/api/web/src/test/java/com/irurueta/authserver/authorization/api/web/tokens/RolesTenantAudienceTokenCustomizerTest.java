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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.password.FindUserAccountUseCase;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import java.util.ArrayList;
import java.util.List;
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
 * Unit tests of {@link RolesTenantAudienceTokenCustomizer}.
 */
class RolesTenantAudienceTokenCustomizerTest {

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

    /** Finds accounts. */
    private FindUserAccountUseCase findUserAccountUseCase;

    /** Contributor of additional claims. */
    private JwtClaimsContributor contributor;

    /** Subject under test. */
    private RolesTenantAudienceTokenCustomizer customizer;

    /**
     * Creates the subject with a mocked use case and contributor.
     */
    @BeforeEach
    void setUp() {
        findUserAccountUseCase = mock(FindUserAccountUseCase.class);
        contributor = mock(JwtClaimsContributor.class);
        customizer = new RolesTenantAudienceTokenCustomizer(findUserAccountUseCase, List.of(contributor));
    }

    /**
     * An authorization code access token gets roles, tenant and the audiences of the client.
     */
    @Test
    void customize_whenAccessTokenOfUser_addsRolesTenantAndAudience() {
        final var account = new UserAccount(UUID.randomUUID(), USERNAME, "x", true, List.of(ROLE_USER), null,
                false, TENANT);
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.of(account));
        final var context = context(OAuth2TokenType.ACCESS_TOKEN, AuthorizationGrantType.AUTHORIZATION_CODE,
                List.of(AUDIENCE));

        customizer.customize(context);

        final var claims = build(context);
        assertEquals(List.of(ROLE_ADMIN, ROLE_USER), claims.getClaim(RolesTenantAudienceTokenCustomizer.ROLES_CLAIM));
        assertEquals(TENANT, claims.getClaim(RolesTenantAudienceTokenCustomizer.TENANT_CLAIM));
        assertEquals(List.of(AUDIENCE), claims.getAudience());
        verify(contributor).contribute(context, context.getClaims());
    }

    /**
     * Factor authorities record how the user signed in; they never become roles, and the roles list is mutable so
     * the authorization store can read it back.
     */
    @Test
    void customize_whenPrincipalHasFactorAuthorities_leavesThemOutOfTheRoles() {
        final Authentication principal = new TestingAuthenticationToken(USERNAME, null,
                List.of(FactorGrantedAuthority.fromAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY),
                        new SimpleGrantedAuthority(ROLE_USER)));
        final var context = context(OAuth2TokenType.ACCESS_TOKEN, AuthorizationGrantType.AUTHORIZATION_CODE,
                List.of(AUDIENCE), principal);

        customizer.customize(context);

        final var roles = build(context).<List<String>>getClaim(RolesTenantAudienceTokenCustomizer.ROLES_CLAIM);
        assertEquals(List.of(ROLE_USER), roles);
        assertEquals(ArrayList.class, roles.getClass());
    }

    /**
     * A user without account gets roles but no tenant.
     */
    @Test
    void customize_whenAccountIsMissing_omitsTenant() {
        when(findUserAccountUseCase.execute(USERNAME)).thenReturn(Optional.empty());
        final var context = context(OAuth2TokenType.ACCESS_TOKEN, AuthorizationGrantType.AUTHORIZATION_CODE,
                List.of());

        customizer.customize(context);

        final var claims = build(context);
        assertNull(claims.getClaim(RolesTenantAudienceTokenCustomizer.TENANT_CLAIM));
        assertNull(claims.getAudience());
    }

    /**
     * The client credentials grant has no user: no roles, no tenant and no account lookup.
     */
    @Test
    void customize_whenClientCredentials_skipsUserClaims() {
        final var context = context(OAuth2TokenType.ACCESS_TOKEN, AuthorizationGrantType.CLIENT_CREDENTIALS,
                List.of(AUDIENCE));

        customizer.customize(context);

        final var claims = build(context);
        assertFalse(claims.hasClaim(RolesTenantAudienceTokenCustomizer.ROLES_CLAIM));
        assertEquals(List.of(AUDIENCE), claims.getAudience());
        verifyNoInteractions(findUserAccountUseCase);
    }

    /**
     * A token that is not an access token is left untouched.
     */
    @Test
    void customize_whenNotAccessToken_doesNothing() {
        final var context = context(new OAuth2TokenType("id_token"), AuthorizationGrantType.AUTHORIZATION_CODE,
                List.of(AUDIENCE));

        customizer.customize(context);

        verifyNoInteractions(findUserAccountUseCase, contributor);
        assertFalse(build(context).hasClaim(RolesTenantAudienceTokenCustomizer.ROLES_CLAIM));
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
            settings.setting(RolesTenantAudienceTokenCustomizer.AUDIENCES_SETTING, audiences);
        }
        final var client = RegisteredClient.withId(UUID.randomUUID().toString()).clientId(CLIENT_ID)
                .authorizationGrantType(grantType).redirectUri(REDIRECT_URI).clientSettings(settings.build()).build();
        final var header = JwsHeader.with(SignatureAlgorithm.RS256);
        final var claims = JwtClaimsSet.builder().subject(USERNAME);
        return JwtEncodingContext.with(header, claims).registeredClient(client).principal(principal)
                .authorizationGrantType(grantType).tokenType(tokenType).build();
    }
}
