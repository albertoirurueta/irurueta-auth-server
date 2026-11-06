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

package com.irurueta.authserver.authorization.api.web.totp;

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Registers the time-based one-time password (and the recovery codes that stand in for it) as an authentication
 * factor: a second one, which only counts once a primary factor has been presented.
 */
@Configuration(proxyBeanMethods = false)
public class TotpFactor {

    /** Identifier of the factor. */
    public static final String ID = "totp";

    /**
     * RFC 8176 {@code amr} value of a one-time password; recovery-code logins report it too.
     */
    public static final String AMR_VALUE = "otp";

    /**
     * Authority granted once a TOTP code or a recovery code has been verified. Spring Security has no constant for
     * it, so it is a custom factor authority ({@code FACTOR_} prefix included).
     */
    public static final String AUTHORITY = "FACTOR_TOTP";

    /**
     * Declares the TOTP factor.
     *
     * @return the factor.
     */
    @Bean
    public AuthenticationFactor totpAuthenticationFactor() {
        return new AuthenticationFactor(ID, AMR_VALUE, AUTHORITY, FactorStrength.SECOND);
    }
}
