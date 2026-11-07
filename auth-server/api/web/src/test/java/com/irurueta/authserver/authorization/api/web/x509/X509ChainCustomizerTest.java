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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.security.cert.X509Certificate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.X509Configurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.x509.X509AuthenticationFilter;
import org.springframework.security.web.authentication.preauth.x509.X509PrincipalExtractor;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Unit tests of {@link X509ChainCustomizer}.
 */
@ExtendWith(MockitoExtension.class)
class X509ChainCustomizerTest {

    /** The documented order of the customizer: after the social login one. */
    private static final int EXPECTED_ORDER = 6;

    /** The fingerprint the extractor reports. */
    private static final String FINGERPRINT = "cd".repeat(32);

    /** Takes the principal of the certificate. */
    @Mock
    private X509PrincipalExtractor principalExtractor;

    /** Loads the account of the certificate. */
    @Mock
    private AuthenticationUserDetailsService<PreAuthenticatedAuthenticationToken> userDetailsService;

    /** Reads a forwarded certificate. */
    @Mock
    private ForwardedCertificateFilter forwardedFilter;

    /** Completes the sign-in. */
    @Mock
    private X509AuthenticationSuccessHandler successHandler;

    /** Authenticates the pre-authenticated token. */
    @Mock
    private AuthenticationManager authenticationManager;

    /**
     * Clears the security context.
     */
    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    /**
     * Verifies the order of the customizer and the path it serves.
     */
    @Test
    void constants_areTheDocumentedOnes() {
        assertEquals(EXPECTED_ORDER, X509ChainCustomizer.ORDER);
        assertEquals("/login/x509", X509ChainCustomizer.LOGIN_PATH);
    }

    /**
     * Verifies that only {@code POST /login/x509} is public: a {@code GET} of the path is not a sign-in.
     */
    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void customize_whenApplied_permitsOnlyTheSignInRequest() {
        final var http = mock(HttpSecurity.class, RETURNS_SELF);
        final var captor = ArgumentCaptor.<Customizer<
                AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry>>captor();
        when(http.authorizeHttpRequests(captor.capture())).thenReturn(http);
        final var registry = mock(AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry.class);
        final var open = mock(AuthorizeHttpRequestsConfigurer.AuthorizedUrl.class);
        final var matcherCaptor = ArgumentCaptor.<RequestMatcher>captor();
        when(registry.requestMatchers(matcherCaptor.capture())).thenReturn(open);

        customizer(forwardedFilter, new X509LoginFilter()).customize(http);
        captor.getValue().customize(registry);

        verify(open).permitAll();
        final var matcher = matcherCaptor.getValue();
        assertTrue(matcher.matches(new MockHttpServletRequest("POST", "/login/x509")));
        assertFalse(matcher.matches(new MockHttpServletRequest("GET", "/login/x509")));
        assertFalse(matcher.matches(new MockHttpServletRequest("POST", "/login")));
    }

    /**
     * Verifies that the filter, the extractor and the user service are handed to the {@code x509} configurer.
     */
    @Test
    @SuppressWarnings("unchecked")
    void customize_whenApplied_configuresTheX509Login() {
        final var http = mock(HttpSecurity.class, RETURNS_SELF);
        final var captor = ArgumentCaptor.<Customizer<X509Configurer<HttpSecurity>>>captor();
        when(http.x509(captor.capture())).thenReturn(http);
        final var x509 = mock(X509Configurer.class, RETURNS_SELF);
        final var filter = new X509LoginFilter();

        customizer(forwardedFilter, filter).customize(http);
        captor.getValue().customize(x509);

        verify(x509).x509AuthenticationFilter(filter);
        verify(x509).x509PrincipalExtractor(principalExtractor);
        verify(x509).authenticationUserDetailsService(userDetailsService);
    }

    /**
     * Verifies that a forwarded certificate is read before the X.509 filter runs.
     */
    @Test
    void customize_whenAProxyMayForward_addsTheForwardedFilterBeforeTheX509One() {
        final var http = mock(HttpSecurity.class, RETURNS_SELF);

        customizer(forwardedFilter, new X509LoginFilter()).customize(http);

        verify(http).addFilterBefore(forwardedFilter, X509AuthenticationFilter.class);
    }

    /**
     * Verifies that without the forwarded transport no such filter is added.
     */
    @Test
    void customize_whenNoProxyMayForward_addsNoForwardedFilter() {
        final var http = mock(HttpSecurity.class, RETURNS_SELF);

        customizer(null, new X509LoginFilter()).customize(http);

        verify(http, never()).addFilterBefore(any(), any());
    }

    /**
     * Verifies that a certificate on the sign-in path is authenticated through the chain's manager, with the
     * multi-factor merge on, and handed to the success handler.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void customize_whenACertificateArrivesAtTheSignInPath_authenticatesAndCallsTheSuccessHandler()
            throws Exception {
        final var http = mock(HttpSecurity.class, RETURNS_SELF);
        when(http.getSharedObject(AuthenticationManager.class)).thenReturn(authenticationManager);
        final var result = mock(Authentication.class);
        when(authenticationManager.authenticate(any())).thenReturn(result);
        when(principalExtractor.extractPrincipal(any())).thenReturn(FINGERPRINT);
        final var filter = new X509LoginFilter();
        customizer(null, filter).customize(http);
        final var request = signInRequest();
        final var response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

        final var captor = ArgumentCaptor.<Authentication>captor();
        verify(authenticationManager).authenticate(captor.capture());
        assertEquals(FINGERPRINT, captor.getValue().getPrincipal());
        verify(successHandler).onAuthenticationSuccess(request, response, result);
    }

    /**
     * Verifies that a certificate on any other path is not looked at.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void customize_whenACertificateArrivesElsewhere_doesNotAuthenticate() throws Exception {
        final var http = mock(HttpSecurity.class, RETURNS_SELF);
        final var filter = new X509LoginFilter();
        customizer(null, filter).customize(http);
        final var request = signInRequest();
        request.setRequestURI("/login");
        request.setServletPath("/login");

        filter.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());

        verify(authenticationManager, never()).authenticate(any());
    }

    /**
     * Verifies that a {@code GET} of the sign-in path, even with a certificate, neither authenticates nor is answered
     * by the filter: it goes on along the chain, whose catch-all rule handles it.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void customize_whenTheSignInPathIsReadWithGet_doesNotAuthenticate() throws Exception {
        final var http = mock(HttpSecurity.class, RETURNS_SELF);
        final var filter = new X509LoginFilter();
        customizer(null, filter).customize(http);
        final var request = signInRequest();
        request.setMethod("GET");
        final var chain = new MockFilterChain();

        filter.doFilter(request, new MockHttpServletResponse(), chain);

        verify(authenticationManager, never()).authenticate(any());
        assertSame(request, chain.getRequest());
    }

    /**
     * Verifies that a certificate nobody owns is sent back to the login page.
     *
     * @throws Exception if the filter fails.
     */
    @Test
    void customize_whenTheCertificateIsRefused_redirectsToTheLoginPageWithError() throws Exception {
        final var http = mock(HttpSecurity.class, RETURNS_SELF);
        when(http.getSharedObject(AuthenticationManager.class)).thenReturn(authenticationManager);
        when(authenticationManager.authenticate(any())).thenThrow(new BadCredentialsException("unknown"));
        when(principalExtractor.extractPrincipal(any())).thenReturn(FINGERPRINT);
        final var filter = new X509LoginFilter();
        customizer(null, filter).customize(http);
        final var response = new MockHttpServletResponse();
        final var chain = new MockFilterChain();

        filter.doFilter(signInRequest(), response, chain);

        assertEquals("/login?error", response.getRedirectedUrl());
        assertEquals(null, chain.getRequest(), "the chain stops after the redirect");
    }

    /**
     * Verifies that the session strategy of the chain reaches the success handler.
     */
    @Test
    void configure_whenTheChainHasASessionStrategy_handsItToTheSuccessHandler() {
        final var http = mock(HttpSecurity.class);
        final var strategy = mock(SessionAuthenticationStrategy.class);
        when(http.getSharedObject(SessionAuthenticationStrategy.class)).thenReturn(strategy);

        new X509ChainCustomizer.SessionStrategyConfigurer(successHandler).configure(http);

        verify(successHandler).setSessionAuthenticationStrategy(strategy);
    }

    /**
     * Verifies that nothing is set when the chain has no session strategy.
     */
    @Test
    void configure_whenTheChainHasNoSessionStrategy_leavesTheSuccessHandlerAlone() {
        final var http = mock(HttpSecurity.class);

        new X509ChainCustomizer.SessionStrategyConfigurer(successHandler).configure(http);

        verify(successHandler, never()).setSessionAuthenticationStrategy(any());
    }

    /**
     * Builds the customizer.
     *
     * @param forwarded the forwarded filter, or {@code null}.
     * @param filter    the X.509 filter.
     * @return the customizer.
     */
    private X509ChainCustomizer customizer(final ForwardedCertificateFilter forwarded, final X509LoginFilter filter) {
        return new X509ChainCustomizer(filter, principalExtractor, userDetailsService, forwarded, successHandler);
    }

    /**
     * Builds a sign-in request that carries a client certificate.
     *
     * @return the request.
     */
    private static MockHttpServletRequest signInRequest() {
        final var request = new MockHttpServletRequest("POST", "/login/x509");
        request.setAttribute(ForwardedCertificateFilter.CERTIFICATE_ATTRIBUTE,
                new X509Certificate[] {mock(X509Certificate.class)});
        return request;
    }
}
