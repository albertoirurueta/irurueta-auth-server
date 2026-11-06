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

import com.irurueta.authserver.authorization.api.web.login.LoginChainCustomizer;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorController;
import com.irurueta.authserver.authorization.api.web.mfa.TrustedDeviceFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

/**
 * Adds the TOTP second factor to the login/UI chain: the second-factor page and the post of its forms are open to a
 * user who has signed in with a password (and only to such a user), and the filters that verify the code and
 * recognise a trusted device are installed before the authorization check. CSRF protection stays on: the forms carry
 * the token.
 */
@RequiredArgsConstructor
public class TotpChainCustomizer implements LoginChainCustomizer {

    /** Filter that recognises a trusted device. */
    private final TrustedDeviceFilter trustedDeviceFilter;

    /** Filter that processes the post of the forms. */
    private final TotpAuthenticationFilter totpAuthenticationFilter;

    /**
     * Customizes the login/UI chain.
     *
     * @param http security builder of the chain.
     */
    @Override
    public void customize(final HttpSecurity http) {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(SecondFactorController.SECOND_FACTOR_PATH, TotpAuthenticationFilter.TOTP_PATH)
                .authenticated());
        http.addFilterBefore(trustedDeviceFilter, AuthorizationFilter.class);
        http.addFilterBefore(totpAuthenticationFilter, AuthorizationFilter.class);
    }
}
