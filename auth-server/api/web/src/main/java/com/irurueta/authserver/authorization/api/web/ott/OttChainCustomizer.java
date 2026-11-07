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
package com.irurueta.authserver.authorization.api.web.ott;

import com.irurueta.authserver.authorization.api.web.login.LoginController;
import com.irurueta.authserver.authorization.api.web.login.LoginChainCustomizer;
import com.irurueta.authserver.authorization.api.web.pages.v1.generated.api.OneTimeTokenPageApi;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.GenerateOneTimeTokenFilter;
import org.springframework.security.web.authentication.ott.GenerateOneTimeTokenRequestResolver;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

// tag::ott-chain[]
/**
 * Adds the one-time token methods to the login/UI chain through {@code http.oneTimeTokenLogin(...)}: the request of a
 * token ({@code POST /ott/generate}), the submission of a magic link token or a numeric code ({@code POST /login/ott})
 * and, as a second factor, the submission of a code ({@code POST /login/second-factor/ott}). The pages the user lands
 * on (where the code is typed, where a magic link is confirmed) are open to everybody and the second-factor post to
 * signed-in users only. The rate limits are applied before anything else of the one-time token flow. CSRF protection
 * stays on: every form carries the token. Once the chain is configured, the second-factor filter gets the chain's
 * session authentication strategy, the one the form login uses (a new session id and a new CSRF token on success).
 * Spring's own default submit page is turned off: the pages are this server's own.
 */
@RequiredArgsConstructor
public class OttChainCustomizer implements LoginChainCustomizer {

    /** Order of this customizer in the login chain, after the TOTP ({@code 1}) and passkey ({@code 2}) ones. */
    public static final int ORDER = 3;

    /** Applies the rate limits to the endpoints. */
    private final OttRateLimitFilter rateLimitFilter;

    /** Resolves the token Spring's filter generates. */
    private final GenerateOneTimeTokenRequestResolver requestResolver;

    /** Delivers the token that was generated. */
    private final OneTimeTokenGenerationSuccessHandler generationSuccessHandler;

    /** Store of the magic link tokens. */
    private final OneTimeTokenService tokenService;

    /** Reads what is posted to the sign-in endpoint. */
    private final AuthenticationConverter authenticationConverter;

    /** Confirms a magic link. */
    private final AuthenticationProvider linkProvider;

    /** Signs a user in with a numeric code. */
    private final AuthenticationProvider codeProvider;

    /** Resumes the interrupted request after a sign-in. */
    private final AuthenticationSuccessHandler successHandler;

    /** Sends the browser back after a failed sign-in. */
    private final AuthenticationFailureHandler failureHandler;

    /** Processes the post of the second-factor code form. */
    private final OttSecondFactorFilter secondFactorFilter;

    /**
     * Customizes the login/UI chain.
     *
     * @param http security builder of the chain.
     */
    @Override
    public void customize(final HttpSecurity http) {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(OttRateLimitFilter.GENERATE_PATH, OneTimeTokenPageApi.PATH_OTT_CODE_PAGE,
                        OneTimeTokenPageApi.PATH_OTT_CODE_PAGE + "/**").permitAll()
                .requestMatchers(OttSecondFactorFilter.SECOND_FACTOR_OTT_PATH).authenticated());
        http.addFilterBefore(rateLimitFilter, GenerateOneTimeTokenFilter.class);
        http.addFilterBefore(secondFactorFilter, AuthorizationFilter.class);
        http.authenticationProvider(codeProvider);
        http.oneTimeTokenLogin(ott -> ott
                .tokenGeneratingUrl(OttRateLimitFilter.GENERATE_PATH)
                .loginProcessingUrl(OneTimeTokenPageApi.PATH_OTT_CODE_PAGE)
                .loginPage(LoginController.LOGIN_PATH)
                .showDefaultSubmitPage(false)
                .tokenService(tokenService)
                .generateRequestResolver(requestResolver)
                .tokenGenerationSuccessHandler(generationSuccessHandler)
                .authenticationConverter(authenticationConverter)
                .authenticationProvider(linkProvider)
                .successHandler(successHandler)
                .failureHandler(failureHandler));
        http.with(new SessionStrategyConfigurer(secondFactorFilter));
    }

    /**
     * Hands the session authentication strategy of the chain to the second-factor filter. The strategy is a shared
     * object of the chain that only exists once every configurer has been initialised (the CSRF configurer adds its
     * {@code CsrfAuthenticationStrategy} to the session management one), so it is read in {@link #configure}, as the
     * form login does for its own filter. Package-private so its test can drive it.
     */
    @RequiredArgsConstructor
    static final class SessionStrategyConfigurer
            extends AbstractHttpConfigurer<SessionStrategyConfigurer, HttpSecurity> {

        /** The filter that gets the strategy. */
        private final OttSecondFactorFilter filter;

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
}
// end::ott-chain[]
