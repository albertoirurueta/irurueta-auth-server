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

package com.irurueta.authserver.authorization.api.web.passkeys;

import com.irurueta.authserver.authorization.api.web.login.LoginChainCustomizer;
import com.irurueta.authserver.authorization.api.web.mfa.MfaAuthorizationManager;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorUserResolver;
import com.irurueta.authserver.authorization.application.mfa.CheckSecondFactorLockoutUseCase;
import com.irurueta.authserver.authorization.application.passkeys.PasskeyProperties;
import java.util.LinkedHashSet;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

/**
 * Customizes the login/UI chain with the passkeys (WebAuthn).
 *
 * <p>{@code http.webAuthn(...)} adds the filters of the four framework endpoints (the authentication options, the
 * authentication, the registration options and the registration) and this class makes them safe for this server:
 * <ul>
 *   <li>the options and the sign-in post are public (CSRF stays on: the page script sends the token), as is the
 *   script;</li>
 *   <li>the registration endpoints (and the account page that drives them) require a session that satisfies the
 *   multi-factor policy of its account, see {@link PasskeyRegistrationAuthorizationManager};</li>
 *   <li>the framework's {@code DELETE /webauthn/register/{id}} is denied, so a passkey can only be removed through
 *   {@code DELETE /api/account/passkeys/{id}}, which asks for a recent multi-factor sign-in, and its default
 *   registration page is turned off;</li>
 *   <li>the WebAuthn filter gets the chain's session strategy (new session id on sign-in) and a user service that
 *   refuses disabled accounts. That user service is set as the chain's shared {@link UserDetailsService}, so it is
 *   chain-wide: every configurer of the login chain that reads the shared object gets the account-status check;</li>
 *   <li>a passkey that completes a second-factor step is refused while the user's second factor is locked, see
 *   {@link PasskeySecondFactorLockoutFilter}. That filter is added before {@link BasicAuthenticationFilter}, the
 *   position the WebAuthn configurer gives its authentication filter later, when the chain is built; being added
 *   first, it runs first.</li>
 * </ul>
 */
@RequiredArgsConstructor
public class PasskeyChainCustomizer implements LoginChainCustomizer {

    /** Order of the customizer: after the TOTP one. */
    public static final int ORDER = 2;

    /** Path of the browser script of the passkeys, served from {@code static/js}. */
    public static final String SCRIPT_PATH = "/js/passkeys.js";

    /** Path that answers the options of an authentication ceremony. */
    public static final String AUTHENTICATION_OPTIONS_PATH = "/webauthn/authenticate/options";

    /** Path that verifies an authentication ceremony. */
    public static final String AUTHENTICATION_PATH = "/login/webauthn";

    /** Relying party settings. */
    private final PasskeyProperties properties;

    /** Applies the multi-factor policy. */
    private final MfaAuthorizationManager mfaAuthorizationManager;

    /** Loads the account of the user a passkey belongs to. */
    private final UserDetailsService userDetailsService;

    /** Resolves the account of the signed-in user, for the lockout check. */
    private final SecondFactorUserResolver secondFactorUserResolver;

    /** Tells whether the second factor of a user is locked. */
    private final CheckSecondFactorLockoutUseCase checkSecondFactorLockoutUseCase;

    /**
     * Customizes the login/UI chain.
     *
     * @param http security builder of the chain.
     */
    // tag::passkeys-chain[]
    @Override
    public void customize(final HttpSecurity http) {
        http.setSharedObject(UserDetailsService.class, new AccountStatusUserDetailsService(userDetailsService));
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(SCRIPT_PATH, AUTHENTICATION_OPTIONS_PATH, AUTHENTICATION_PATH).permitAll()
                .requestMatchers(HttpMethod.DELETE, PasskeyRegistrationAuthorizationManager.REGISTRATION_PATH + "/**")
                .denyAll()
                .requestMatchers(PasskeysPageController.PASSKEYS_PATH).access(mfaAuthorizationManager));
        http.addFilterBefore(
                new PasskeyRegistrationFilter(new PasskeyRegistrationAuthorizationManager(mfaAuthorizationManager)),
                AuthorizationFilter.class);
        http.addFilterBefore(
                new PasskeySecondFactorLockoutFilter(secondFactorUserResolver, checkSecondFactorLockoutUseCase),
                BasicAuthenticationFilter.class);
        http.webAuthn(webAuthn -> webAuthn
                .rpName(properties.rpName())
                .rpId(properties.rpId())
                .allowedOrigins(new LinkedHashSet<>(properties.allowedOrigins()))
                .disableDefaultRegistrationPage(true)
                .addObjectPostProcessor(new SessionStrategyPostProcessor(http)));
    }
    // end::passkeys-chain[]
}
