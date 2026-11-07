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
import java.util.function.Function;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Chooses the validator of the ID token of each registration: the framework's {@link OidcIdTokenValidator}, plus the
 * {@link EntraIssuerValidator} for Microsoft (registered without an issuer, see {@link ClientRegistrationMapper}).
 * It is the {@code jwtValidatorFactory} of the {@code OidcIdTokenDecoderFactory}, which replaces the default validator,
 * so the framework's checks of the audience, the timestamps and the subject stay.
 */
@RequiredArgsConstructor
public class IdTokenValidatorFactory implements Function<ClientRegistration, OAuth2TokenValidator<Jwt>> {

    /** Settings of the providers, for the tenants Microsoft is limited to. */
    private final SocialProperties properties;

    /**
     * Builds the validator of a registration.
     *
     * @param registration the registration the token was issued for.
     * @return the validator.
     */
    @Override
    public OAuth2TokenValidator<Jwt> apply(final ClientRegistration registration) {
        final var standard = new OidcIdTokenValidator(registration);
        if (!IdentityProvider.MICROSOFT.id().equals(registration.getRegistrationId())) {
            return standard;
        }
        final var tenants = properties.find(IdentityProvider.MICROSOFT)
                .map(SocialProperties.Provider::permittedTenants).orElse(List.of());
        return new DelegatingOAuth2TokenValidator<>(standard, new EntraIssuerValidator(tenants));
    }
}
