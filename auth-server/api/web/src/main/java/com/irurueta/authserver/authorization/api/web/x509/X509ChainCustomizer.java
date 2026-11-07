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
package com.irurueta.authserver.authorization.api.web.x509;

import com.irurueta.authserver.authorization.api.web.login.LoginChainCustomizer;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

// tag::x509-chain[]
/**
 * Adds the sign-in with a client certificate to the login/UI chain through {@code http.x509(...)}. The filter only
 * looks at {@code GET /login/x509}, a path the browser is sent to on the TLS port that requests a certificate (or
 * behind the proxy that forwards one), so every other request of the chain is untouched; a certificate that is bound
 * to an account signs it in and resumes the interrupted request, anything else goes back to the login page. The path
 * is open to everybody, because it is where the certificate is checked, and the rest of the chain is not touched.
 * When a proxy may forward the certificate, {@link ForwardedCertificateFilter} runs first. Once the chain is
 * configured, the success handler gets the chain's session authentication strategy, the one the form login uses.
 */
@RequiredArgsConstructor
public class X509ChainCustomizer implements LoginChainCustomizer {

    /** Order of the customizer: after the social login one. */
    public static final int ORDER = 6;

    /** Path of the sign-in with a certificate, which is served by the security filter. */
    public static final String LOGIN_PATH = "/login/x509";

    /** Where a failed sign-in goes. */
    static final String FAILURE_URL = "/login?error";

    /** The filter that authenticates the certificate. */
    private final X509LoginFilter filter;

    /** Takes the principal of the certificate. */
    private final X509PrincipalExtractor principalExtractor;

    /** Loads the account of the certificate. */
    private final AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> userDetailsService;

    /** The filter that reads a forwarded certificate, or {@code null} when the transport is off. */
    private final ForwardedCertificateFilter forwardedFilter;

    /** Completes the sign-in. */
    private final X509AuthenticationSuccessHandler successHandler;

    /**
     * Customizes the login/UI chain.
     *
     * @param http security builder of the chain.
     */
    @Override
    public void customize(final HttpSecurity http) {
        final var loginRequest = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, LOGIN_PATH);
        http.authorizeHttpRequests(authorize -> authorize.requestMatchers(loginRequest).permitAll());
        prepare(filter, loginRequest, http);
        if (forwardedFilter != null) {
            http.addFilterBefore(forwardedFilter, X509AuthenticationFilter.class);
        }
        http.x509(x509 -> x509
                .x509AuthenticationFilter(filter)
                .x509PrincipalExtractor(principalExtractor)
                .authenticationUserDetailsService(userDetailsService));
        http.with(new SessionStrategyConfigurer(successHandler));
    }

    /**
     * Sets up the filter, which the {@code x509} configurer takes as it is.
     *
     * @param loginFilter  the filter.
     * @param loginRequest matcher of the sign-in requests.
     * @param http         security builder of the chain, whose authentication manager the filter uses once built.
     */
    private void prepare(final X509LoginFilter loginFilter, final RequestMatcher loginRequest,
            final HttpSecurity http) {
        loginFilter.setPrincipalExtractor(principalExtractor);
        loginFilter.setRequiresAuthenticationRequestMatcher(loginRequest);
        loginFilter.setMfaEnabled(true);
        loginFilter.setAuthenticationSuccessHandler(successHandler);
        loginFilter.setAuthenticationFailureHandler(
                (request, response, exception) -> response.sendRedirect(request.getContextPath() + FAILURE_URL));
        // the chain's manager only exists once the chain is built, so it is read when a request arrives
        loginFilter.setAuthenticationManager(authentication ->
                http.getSharedObject(AuthenticationManager.class)
                        .authenticate(authentication));
    }

    /**
     * Hands the session authentication strategy of the chain to the success handler. The strategy is a shared object
     * of the chain that only exists once every configurer has been initialised (the CSRF configurer adds its
     * {@code CsrfAuthenticationStrategy} to the session management one), so it is read in {@code configure}, as the
     * form login does for its own filter. Package-private so its test can drive it.
     */
    @RequiredArgsConstructor
    static final class SessionStrategyConfigurer
            extends AbstractHttpConfigurer<SessionStrategyConfigurer, HttpSecurity> {

        /** The handler that gets the strategy. */
        private final X509AuthenticationSuccessHandler handler;

        /**
         * Sets the shared strategy, when the chain has one, on the handler.
         *
         * @param http security builder of the chain.
         */
        @Override
        public void configure(final HttpSecurity http) {
            final var strategy = http.getSharedObject(SessionAuthenticationStrategy.class);
            if (strategy != null) {
                handler.setSessionAuthenticationStrategy(strategy);
            }
        }
    }
}
// end::x509-chain[]
