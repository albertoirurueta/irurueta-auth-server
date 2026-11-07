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
import com.irurueta.authserver.authorization.domain.social.VerifiedEmailLookup;
import java.util.List;
import java.util.Objects;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.user.OAuth2User;

// tag::social-oauth2-user-service[]
/**
 * The user service of the providers that are plain OAuth 2.0 (GitHub), which have no ID token: the framework's service
 * reads the profile from the provider's API, the verified primary e-mail address is read from {@code /user/emails}
 * (through the domain port {@link VerifiedEmailLookup}, implemented by the GitHub adapter of
 * {@code infrastructure/github} with a client generated from the contract of that GitHub operation), the account is
 * resolved (found, linked by verified e-mail or provisioned, and refused when it may not sign in) and the principal
 * becomes the local one, named after the account. The stable subject is GitHub's numeric id, never the login name or
 * the e-mail address, which the user can change.
 */
@RequiredArgsConstructor
public class FederatedOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    /** Attributes of GitHub's profile that are kept in the session: scalars only. */
    static final List<String> KEPT_ATTRIBUTES = List.of("id", "login", "name", "avatar_url");

    /** Message of the failure when the framework's service answers no user. */
    private static final String MISSING_USER = "The provider's user is missing";

    /** The framework's service, which reads the profile. */
    private final OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate;

    /** Reads the verified primary e-mail address. */
    private final VerifiedEmailLookup verifiedEmailLookup;

    /** Resolves the local account. */
    private final FederatedAccountResolver accountResolver;

    /** Builds the local principal. */
    private final FederatedUserMapper userMapper;

    /**
     * Loads the user of a sign-in.
     *
     * @param request the request, with the registration and the access token.
     * @return the local principal.
     * @throws OAuth2AuthenticationException if the provider is not GitHub or the sign-in is refused.
     */
    @Override
    public OAuth2User loadUser(final OAuth2UserRequest request) throws OAuth2AuthenticationException {
        final var registration = request.getClientRegistration();
        if (!IdentityProvider.GITHUB.id().equals(registration.getRegistrationId())) {
            throw new OAuth2AuthenticationException(
                    new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, "Unknown provider", null));
        }
        final var upstream = Objects.requireNonNull(delegate.loadUser(request), MISSING_USER);
        final var email = verifiedEmailLookup.verifiedPrimaryEmail(
                registration.getProviderDetails().getUserInfoEndpoint().getUri(),
                request.getAccessToken().getTokenValue());
        final var account = accountResolver.resolve(
                IdentityProvider.GITHUB, upstream.getName(), email.orElse(null), email.isPresent());
        return userMapper.toLocalUser(
                upstream, KEPT_ATTRIBUTES, email.orElse(null), account.getUsername(), account.getAuthorities());
    }
}
// end::social-oauth2-user-service[]
