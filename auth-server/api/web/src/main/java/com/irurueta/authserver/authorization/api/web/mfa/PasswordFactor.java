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
import org.springframework.security.core.authority.FactorGrantedAuthority;

/**
 * Registers the password as an authentication factor: a primary one, which needs a second factor to satisfy the
 * policy.
 */
@Configuration(proxyBeanMethods = false)
public class PasswordFactor {

    /** Identifier of the factor. */
    public static final String ID = "password";

    /** RFC 8176 {@code amr} value of a password. */
    public static final String AMR_VALUE = "pwd";

    /**
     * Declares the password factor, granted by Spring Security as {@link FactorGrantedAuthority#PASSWORD_AUTHORITY}.
     *
     * @return the factor.
     */
    @Bean
    public AuthenticationFactor passwordAuthenticationFactor() {
        return new AuthenticationFactor(ID, AMR_VALUE, FactorGrantedAuthority.PASSWORD_AUTHORITY,
                FactorStrength.PRIMARY);
    }
}
