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
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

/**
 * Adds the TOTP second factor to the login/UI chain: the second-factor page and the post of its forms are open to a
 * user who has signed in with a password (and only to such a user), and the filters that verify the code and
 * recognise a trusted device are installed before the authorization check. CSRF protection stays on: the forms carry
 * the token. Once the chain is configured, the TOTP filter gets the chain's session authentication strategy, the one
 * the form login uses (a new session id and a new CSRF token on success).
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
        http.with(new SessionStrategyConfigurer(totpAuthenticationFilter));
    }

    // tag::totp-session-strategy[]
    /**
     * Hands the session authentication strategy of the chain to the TOTP filter. The strategy is a shared object of
     * the chain that only exists once every configurer has been initialised (the CSRF configurer adds its
     * {@code CsrfAuthenticationStrategy} to the session management one), so it is read in {@link #configure}, as the
     * form login does for its own filter. Package-private so its test can drive it.
     */
    @RequiredArgsConstructor
    static final class SessionStrategyConfigurer
            extends AbstractHttpConfigurer<SessionStrategyConfigurer, HttpSecurity> {

        /** The filter that gets the strategy. */
        private final TotpAuthenticationFilter filter;

        /**
         * Sets the shared strategy, when the chain has one, on the filter.
         *
         * @param http security builder of the chain.
         */
        @Override
        public void configure(final HttpSecurity http) {
            final var strategy = http.getSharedObject(SessionAuthenticationStrategy.class);
            if (strategy != null) {
                filter.setSessionAuthenticationStrategy(strategy);
            }
        }
    }
    // end::totp-session-strategy[]
}
