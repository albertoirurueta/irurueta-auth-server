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

import static com.irurueta.authserver.authorization.api.web.consent.ConsentController.CONSENT_PATH;

import com.irurueta.authserver.authorization.api.web.login.LoginChainCustomizer;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.AuthenticationEntryPoint;

/**
 * Applies the multi-factor policy to the login/UI chain: the consent page needs the factors the policy asks for, and a
 * user who lacks a registered second factor is sent to the second-factor page instead of getting a 403.
 */
@RequiredArgsConstructor
public class MfaLoginChainCustomizer implements LoginChainCustomizer {

    /** Manager that applies the policy. */
    private final MfaAuthorizationManager authorizationManager;

    /** Registry of the known factors. */
    private final AuthenticationFactorRegistry factorRegistry;

    /** Entry point that sends the user to the second-factor page. */
    private final AuthenticationEntryPoint secondFactorEntryPoint;

    /**
     * Customizes the login/UI chain.
     *
     * @param http security builder of the chain.
     */
    @Override
    public void customize(final HttpSecurity http) {
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers(CONSENT_PATH).access(authorizationManager));
        http.exceptionHandling(exceptions -> factorRegistry.withStrength(
                FactorStrength.SECOND).forEach(factor -> exceptions
                .defaultDeniedHandlerForMissingAuthority(secondFactorEntryPoint, factor.authority())));
    }
}
