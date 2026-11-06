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

import com.irurueta.authserver.authorization.api.web.ProtocolChainCustomizer;
import com.irurueta.authserver.authorization.api.web.login.LoginChainCustomizer;
import com.irurueta.authserver.authorization.application.mfa.IsClientMfaRequiredUseCase;
import com.irurueta.authserver.authorization.application.mfa.IsUserMfaRequiredUseCase;
import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.MfaPolicy;
import java.time.Clock;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authorization.EnableMultiFactorAuthentication;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

/**
 * Wires multi-factor authentication: Spring Security's multi-factor support (it enables the entry points for a missing
 * factor authority; the factors are not required globally, because the {@link MfaAuthorizationManager} requires them
 * only when the client or the user asks for it), the registry of {@link AuthenticationFactor} beans, the policy
 * manager, and its application to the login chain and to {@code /oauth2/authorize}.
 *
 * <p>A login method adds its factor by declaring an {@link AuthenticationFactor} bean (see
 * {@link PasswordFactor}); nothing here is edited.
 */
@Configuration(value = "mfaWebConfiguration", proxyBeanMethods = false)
@EnableMultiFactorAuthentication(authorities = {})
public class MfaConfiguration {

    /**
     * Builds the registry of the known factors.
     *
     * @param factors every {@link AuthenticationFactor} bean.
     * @return the registry.
     */
    @Bean
    public AuthenticationFactorRegistry authenticationFactorRegistry(final List<AuthenticationFactor> factors) {
        return new AuthenticationFactorRegistry(factors);
    }

    /**
     * Builds the entry point that sends a user to the second-factor page, resuming the saved request afterwards.
     *
     * @return the entry point, sharing the session request cache of the form login.
     */
    @Bean
    public SecondFactorRequiredEntryPoint secondFactorRequiredEntryPoint() {
        return new SecondFactorRequiredEntryPoint(new HttpSessionRequestCache());
    }

    /**
     * Builds the manager that applies the multi-factor policy.
     *
     * @param mfaPolicy                  the policy.
     * @param factorRegistry             the registry of the known factors.
     * @param isUserMfaRequiredUseCase   tells whether a user's account requires a second factor.
     * @param isClientMfaRequiredUseCase tells whether the client of a request requires a second factor.
     * @return the manager.
     */
    @Bean
    public MfaAuthorizationManager mfaAuthorizationManager(final MfaPolicy mfaPolicy,
            final AuthenticationFactorRegistry factorRegistry, final IsUserMfaRequiredUseCase isUserMfaRequiredUseCase,
            final IsClientMfaRequiredUseCase isClientMfaRequiredUseCase) {
        return new MfaAuthorizationManager(mfaPolicy, factorRegistry, isUserMfaRequiredUseCase,
                isClientMfaRequiredUseCase);
    }

    /**
     * Applies the policy to the login/UI chain.
     *
     * @param authorizationManager   the manager.
     * @param factorRegistry         the registry of the known factors.
     * @param secondFactorEntryPoint the entry point of the second-factor page.
     * @return the customizer.
     */
    @Bean
    @Order(0)
    public LoginChainCustomizer mfaLoginChainCustomizer(final MfaAuthorizationManager authorizationManager,
            final AuthenticationFactorRegistry factorRegistry,
            final SecondFactorRequiredEntryPoint secondFactorEntryPoint) {
        return new MfaLoginChainCustomizer(authorizationManager, factorRegistry, secondFactorEntryPoint);
    }

    /**
     * Applies the policy to {@code /oauth2/authorize}.
     *
     * @param authorizationManager     the manager.
     * @param secondFactorEntryPoint   the entry point of the second-factor page.
     * @param reauthenticationEntryPoint the entry point that forces a new sign-in.
     * @return the customizer.
     */
    @Bean
    @Order(0)
    public ProtocolChainCustomizer mfaProtocolChainCustomizer(final MfaAuthorizationManager authorizationManager,
            final SecondFactorRequiredEntryPoint secondFactorEntryPoint,
            final ReauthenticationEntryPoint reauthenticationEntryPoint) {
        return new MfaProtocolChainCustomizer(authorizationManager,
                new SecondFactorErrorResponseHandler(secondFactorEntryPoint, reauthenticationEntryPoint));
    }

    /**
     * Builds the entry point that forces a new sign-in, resuming the saved request afterwards.
     *
     * @return the entry point, sharing the session request cache of the form login.
     */
    @Bean
    public ReauthenticationEntryPoint reauthenticationEntryPoint() {
        return new ReauthenticationEntryPoint(new HttpSessionRequestCache(),
                new HttpSessionSecurityContextRepository());
    }

    /**
     * Applies step-up authentication ({@code acr_values}, {@code max_age}) to {@code /oauth2/authorize}.
     *
     * @param factorTimeline reads the counted factors of the session and their instants.
     * @param clock          the clock the age of the authentication is measured with.
     * @return the customizer.
     */
    @Bean
    @Order(1)
    public ProtocolChainCustomizer stepUpProtocolChainCustomizer(final FactorTimeline factorTimeline,
            final Clock clock) {
        return new StepUpProtocolChainCustomizer(new StepUpAuthorizationRequestConverter(factorTimeline, clock));
    }
}
