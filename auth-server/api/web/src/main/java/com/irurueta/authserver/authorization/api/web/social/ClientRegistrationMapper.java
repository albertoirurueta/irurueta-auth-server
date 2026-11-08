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
import java.util.List;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.stereotype.Component;

// tag::social-client-registrations[]
/**
 * Maps the settings of the enabled providers onto the client registrations Spring Security's {@code oauth2Login}
 * needs. The client secret of every registration comes from {@link SocialProperties} (so from the environment), and
 * the Apple registration carries none: its secret is a JWT generated for each token request
 * ({@link AppleClientSecretGenerator}).
 *
 * <ul>
 *   <li>Google is an OpenID Connect provider with the framework's defaults;</li>
 *   <li>Microsoft Entra ID is registered <em>without</em> an issuer: a multi-tenant application's tokens carry the
 *   issuer of the tenant the user belongs to, so the framework's single issuer comparison would reject them all;
 *   {@link EntraIssuerValidator} checks the issuer against the token's tenant instead;</li>
 *   <li>Apple is an OpenID Connect provider without a UserInfo endpoint, whose client authentication is the signed
 *   secret posted with the other parameters;</li>
 *   <li>GitHub is plain OAuth 2.0 (no ID token): the user is read from its API, with the {@code user:email} scope the
 *   verified primary address needs.</li>
 * </ul>
 */
@Component
public class ClientRegistrationMapper {

    /** Redirect URI template of every registration. */
    public static final String REDIRECT_URI = "{baseUrl}/login/oauth2/code/{registrationId}";

    /** Base URL of Microsoft Entra ID. */
    static final String ENTRA_BASE_URL = "https://login.microsoftonline.com/";

    /** Base URL of Sign in with Apple. */
    static final String APPLE_BASE_URL = "https://appleid.apple.com";

    /** OAuth scope that lets GitHub's API list the e-mail addresses of the user. */
    static final String GITHUB_EMAIL_SCOPE = "user:email";

    /** OAuth scope that lets GitHub's API read the profile of the user. */
    static final String GITHUB_USER_SCOPE = "read:user";

    /** Scope Sign in with Apple uses to hand over the name of the user (it has no {@code profile} scope). */
    static final String APPLE_NAME_SCOPE = "name";

    /** OIDC UserInfo endpoint of Microsoft. */
    static final String MICROSOFT_USER_INFO_URI = "https://graph.microsoft.com/oidc/userinfo";

    /**
     * Maps the enabled providers.
     *
     * @param properties settings of the providers.
     * @return one registration per enabled provider, in the order of {@link IdentityProvider}; empty when none is
     *         enabled.
     */
    public List<ClientRegistration> toRegistrations(final SocialProperties properties) {
        return properties.enabledProviders().entrySet().stream()
                .map(entry -> toRegistration(entry.getKey(), entry.getValue()))
                .toList();
    }

    /**
     * Maps one provider.
     *
     * @param provider the provider.
     * @param settings its settings.
     * @return the registration.
     */
    public ClientRegistration toRegistration(
            final IdentityProvider provider, final SocialProperties.Provider settings) {
        return switch (provider) {
            case GOOGLE -> CommonOAuth2Provider.GOOGLE.getBuilder(provider.id())
                    .clientId(settings.clientId())
                    .clientSecret(settings.clientSecret())
                    .build();
            case GITHUB -> CommonOAuth2Provider.GITHUB.getBuilder(provider.id())
                    .clientId(settings.clientId())
                    .clientSecret(settings.clientSecret())
                    .scope(GITHUB_USER_SCOPE, GITHUB_EMAIL_SCOPE)
                    .build();
            case MICROSOFT -> microsoft(settings);
            case APPLE -> apple(settings);
        };
    }

    /**
     * Builds the Microsoft Entra ID registration, without an issuer (see the class description).
     *
     * @param settings settings of the provider.
     * @return the registration.
     */
    private static ClientRegistration microsoft(final SocialProperties.Provider settings) {
        final var tenantUrl = ENTRA_BASE_URL + settings.tenant();
        return ClientRegistration.withRegistrationId(IdentityProvider.MICROSOFT.id())
                .clientName("Microsoft")
                .clientId(settings.clientId())
                .clientSecret(settings.clientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(REDIRECT_URI)
                .scope(OidcScopes.OPENID, OidcScopes.PROFILE, OidcScopes.EMAIL)
                .authorizationUri(tenantUrl + "/oauth2/v2.0/authorize")
                .tokenUri(tenantUrl + "/oauth2/v2.0/token")
                .jwkSetUri(tenantUrl + "/discovery/v2.0/keys")
                .userInfoUri(MICROSOFT_USER_INFO_URI)
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .build();
    }

    /**
     * Builds the Sign in with Apple registration. Its client secret is empty here: the token request carries the
     * signed JWT instead.
     *
     * @param settings settings of the provider.
     * @return the registration.
     */
    private static ClientRegistration apple(final SocialProperties.Provider settings) {
        return ClientRegistration.withRegistrationId(IdentityProvider.APPLE.id())
                .clientName("Apple")
                .clientId(settings.clientId())
                .clientSecret("")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri(REDIRECT_URI)
                .scope(OidcScopes.OPENID, APPLE_NAME_SCOPE, OidcScopes.EMAIL)
                .authorizationUri(APPLE_BASE_URL + "/auth/authorize")
                .tokenUri(APPLE_BASE_URL + "/auth/token")
                .jwkSetUri(APPLE_BASE_URL + "/auth/keys")
                .issuerUri(APPLE_BASE_URL)
                .userNameAttributeName(IdTokenClaimNames.SUB)
                .build();
    }
}
// end::social-client-registrations[]
