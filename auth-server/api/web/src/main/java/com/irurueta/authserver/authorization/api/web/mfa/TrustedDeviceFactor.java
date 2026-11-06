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
package com.irurueta.authserver.authorization.api.web.mfa;

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

// tag::mfa-trusted-device-factor[]
/**
 * Registers the trusted device as an authentication factor of strength {@link FactorStrength#REMEMBERED}: together
 * with the password it satisfies the sign-in policy, so a trusted browser is not asked for the code again, but it is
 * never reported in {@code amr}, {@code acr} or {@code auth_time} and never satisfies a step-up request
 * ({@code acr_values} asking for the multi-factor class, {@code max_age}), which still needs a real second factor.
 */
@Configuration(proxyBeanMethods = false)
public class TrustedDeviceFactor {

    /** Identifier of the factor. */
    public static final String ID = "trusted-device";

    /**
     * Value the factor would have in {@code amr}. RFC 8176 has none for a remembered device, and the factor is never
     * reported, so it is only a label.
     */
    public static final String AMR_VALUE = "trusted-device";

    /** Authority granted by {@link TrustedDeviceFilter} when the browser presents a valid trusted-device cookie. */
    public static final String AUTHORITY = "FACTOR_TRUSTED_DEVICE";

    /**
     * Declares the trusted-device factor.
     *
     * @return the factor.
     */
    @Bean
    public AuthenticationFactor trustedDeviceAuthenticationFactor() {
        return new AuthenticationFactor(ID, AMR_VALUE, AUTHORITY, FactorStrength.REMEMBERED);
    }
}
// end::mfa-trusted-device-factor[]
