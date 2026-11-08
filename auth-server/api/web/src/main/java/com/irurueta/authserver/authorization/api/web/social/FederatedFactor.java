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

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registers the sign-in with an external provider as an authentication factor, in two flavours that are never held
 * together by one session:
 * <ul>
 *   <li>{@link #AUTHORITY} ({@code fed}, a {@link FactorStrength#PRIMARY} factor): the normal case. The provider
 *   proved the user, but the server does not know how, so the normal second-factor flow applies;</li>
 *   <li>{@link #STRONG_AUTHORITY} ({@code fed}, {@link FactorStrength#PRIMARY_STRONG}): granted instead of the first
 *   only when the provider is marked {@code trust-mfa} <em>and</em> its upstream {@code amr} contains {@code mfa}, so
 *   the sign-in satisfies the multi-factor policy on its own, like a passkey. Unlike a passkey it is also
 *   {@link AuthenticationFactor#multiFactor() multi-factor alone}: the provider proved several factors, so the
 *   session reaches the multi-factor {@code acr} and passes a step-up without a local second factor.</li>
 * </ul>
 * Both report the same {@code amr} value, so the tokens read {@code fed} either way (plus {@code mfa} and the upstream
 * values for the strong one, see {@link IdpClaimsContributor}).
 */
@Configuration(proxyBeanMethods = false)
public class FederatedFactor {

    /** Authority of a federated sign-in, a primary factor. */
    public static final String AUTHORITY = "FACTOR_FEDERATED";

    /** Authority of a federated sign-in whose provider proved several factors and is trusted for it. */
    public static final String STRONG_AUTHORITY = "FACTOR_FEDERATED_MFA";

    /** RFC 8176 {@code amr} value of a federated sign-in. */
    public static final String AMR_VALUE = "fed";

    // tag::social-factor[]
    /**
     * Declares the federated factor.
     *
     * @return the factor.
     */
    @Bean
    public AuthenticationFactor federatedAuthenticationFactor() {
        return new AuthenticationFactor("federated", AMR_VALUE, AUTHORITY, FactorStrength.PRIMARY);
    }

    /**
     * Declares the federated factor of a trusted provider that proved several factors.
     *
     * @return the factor.
     */
    @Bean
    public AuthenticationFactor federatedStrongAuthenticationFactor() {
        return new AuthenticationFactor("federated-mfa", AMR_VALUE, STRONG_AUTHORITY, FactorStrength.PRIMARY_STRONG,
                true);
    }
    // end::social-factor[]
}
