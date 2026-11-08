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

package com.irurueta.authserver.authorization.api.web.social;

import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

// tag::social-oidc-user-service[]
/**
 * The user service of the OpenID Connect providers (Google, Microsoft, Apple): the framework's service loads the user
 * as it always does (the ID token, and the UserInfo endpoint where the provider has one), then the account is resolved
 * (found, linked by verified e-mail or provisioned, and refused when it may not sign in) and the principal becomes the
 * local one, named after the account.
 */
@RequiredArgsConstructor
public class FederatedOidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

    /** Message of the failure when the framework's service answers no user. */
    private static final String MISSING_USER = "The provider's user is missing";

    /** Message of the failure when the user has no subject. */
    private static final String MISSING_SUBJECT = "The provider's subject is missing";

    /** The framework's service, which loads the user the provider describes. */
    private final OAuth2UserService<OidcUserRequest, OidcUser> delegate;

    /** Resolves the local account. */
    private final FederatedAccountResolver accountResolver;

    /** Builds the local principal. */
    private final FederatedUserMapper userMapper;

    /**
     * Loads the user of a sign-in.
     *
     * @param request the request, with the registration, the access token and the ID token.
     * @return the local principal.
     * @throws OAuth2AuthenticationException if the provider is unknown or the sign-in is refused.
     */
    @Override
    public OidcUser loadUser(final OidcUserRequest request) throws OAuth2AuthenticationException {
        final var provider = IdentityProvider.fromId(request.getClientRegistration().getRegistrationId())
                .orElseThrow(() -> new OAuth2AuthenticationException(
                        new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Unknown provider", null)));
        final var upstream = Objects.requireNonNull(delegate.loadUser(request), MISSING_USER);
        final var subject = Objects.requireNonNull(upstream.getSubject(), MISSING_SUBJECT);
        final var account = accountResolver.resolve(
                provider, subject, upstream.getEmail(), userMapper.emailVerified(upstream));
        return userMapper.toLocalUser(upstream, account.getUsername(), account.getAuthorities());
    }
}
// end::social-oidc-user-service[]
