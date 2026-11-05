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

import com.irurueta.authserver.authorization.application.password.FindUserAccountUseCase;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenClaimNames;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.stereotype.Component;

// tag::tokens-claims[]
/**
 * The claims this server adds to the tokens it issues, whatever their format, so the self-contained (JWT) access
 * tokens and the reference (opaque) ones carry the same claims: {@link RolesTenantAudienceTokenCustomizer} applies it
 * to the JWTs and {@link ReferenceTokenClaimsCustomizer} to the claims stored for a reference token (which the
 * introspection endpoint returns).
 *
 * <p>An access token gets {@code roles}, {@code tenant} and {@code aud}: the roles are the authorities of the user,
 * the tenant comes from the user account, the audiences from the {@value #AUDIENCES_SETTING} custom setting of the
 * client. Tokens of the client credentials grant have no user, so they get no roles and no tenant. An ID token gets
 * none of them. Then every {@link JwtClaimsContributor}, in order, adds its own claims to the access and ID tokens
 * (it can tell them apart with {@link OAuth2TokenContext#getTokenType()}); no other token is touched.
 */
@Component
@RequiredArgsConstructor
public class IssuedTokenClaims {

    /**
     * Name of the custom client setting that holds the audiences of the access tokens. It is the same name the
     * persistence adapter writes (that module cannot be referenced from here).
     */
    public static final String AUDIENCES_SETTING = "settings.client.audiences";

    /** Name of the claim that holds the roles of the user. */
    public static final String ROLES_CLAIM = "roles";

    /** Name of the claim that holds the tenant of the user. */
    public static final String TENANT_CLAIM = "tenant";

    /** Type of the OpenID Connect ID token. */
    static final OAuth2TokenType ID_TOKEN = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);

    /** Prefix of the authorities that record how a user authenticated, such as {@code FACTOR_PASSWORD}. */
    private static final String FACTOR_PREFIX = "FACTOR_";

    /** Finds the account of the user. */
    private final FindUserAccountUseCase findUserAccountUseCase;

    /** Contributors of additional claims, in order. */
    private final List<JwtClaimsContributor> contributors;

    /**
     * Adds the claims of the token being issued.
     *
     * @param context the token context, with the token type, the principal, the client and the grant type.
     * @param claims  the mutable claims of the token being built.
     */
    public void apply(final OAuth2TokenContext context, final Map<String, Object> claims) {
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            addAccessTokenClaims(context, claims);
        } else if (!ID_TOKEN.equals(context.getTokenType())) {
            return;
        }
        contributors.forEach(contributor -> contributor.contribute(context, claims));
    }

    /**
     * Adds the roles, the tenant and the audiences of an access token.
     *
     * @param context the token context.
     * @param claims  the mutable claims of the token being built.
     */
    private void addAccessTokenClaims(final OAuth2TokenContext context, final Map<String, Object> claims) {
        if (context.getAuthorizationGrantType() != null
                && !AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
            final Authentication principal =
                    Objects.requireNonNull(context.getPrincipal(), "a user grant has a principal");
            // factor authorities (FACTOR_PASSWORD, ...) record how the user signed in; they are not roles. The
            // list is a mutable one on purpose: the authorization store only deserializes allow-listed types, and
            // an immutable list copy (Stream.toList) is not one of them.
            claims.put(ROLES_CLAIM, principal.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .filter(authority -> !authority.startsWith(FACTOR_PREFIX)).sorted()
                    .collect(Collectors.toCollection(ArrayList::new)));
            findUserAccountUseCase.execute(principal.getName())
                    .ifPresent(account -> claims.put(TENANT_CLAIM, account.tenant()));
        }
        if (context.getRegisteredClient().getClientSettings().getSetting(AUDIENCES_SETTING)
                instanceof List<?> audiences && !audiences.isEmpty()) {
            claims.put(OAuth2TokenClaimNames.AUD, audiences.stream().map(String::valueOf)
                    .collect(Collectors.toCollection(ArrayList::new)));
        }
    }
}
// end::tokens-claims[]
