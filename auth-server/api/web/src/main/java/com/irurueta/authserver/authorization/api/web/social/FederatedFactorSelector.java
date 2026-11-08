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
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;

// tag::social-factor-selector[]
/**
 * Decides which factor a federated sign-in proved: the strong one when the provider is trusted for its multi-factor
 * authentication ({@code authserver.social.providers.<id>.trust-mfa}) and its upstream {@code amr} contains
 * {@code mfa}, the ordinary one otherwise. An upstream claim the server was not told to trust is never believed.
 */
@RequiredArgsConstructor
public class FederatedFactorSelector {

    /** Settings of the providers, for the trust. */
    private final SocialProperties properties;

    /** Reads the upstream {@code amr}. */
    private final FederatedUserMapper userMapper;

    /**
     * Selects the factor of a sign-in.
     *
     * @param token the authentication of the sign-in.
     * @return {@link FederatedFactor#STRONG_AUTHORITY} or {@link FederatedFactor#AUTHORITY}.
     */
    public String authorityOf(final OAuth2AuthenticationToken token) {
        return IdentityProvider.fromId(token.getAuthorizedClientRegistrationId())
                .map(properties::trust)
                .filter(trust -> trust.isStrong(userMapper.upstreamAmr(Objects.requireNonNull(token.getPrincipal()))))
                .map(trust -> FederatedFactor.STRONG_AUTHORITY)
                .orElse(FederatedFactor.AUTHORITY);
    }
}
// end::social-factor-selector[]
