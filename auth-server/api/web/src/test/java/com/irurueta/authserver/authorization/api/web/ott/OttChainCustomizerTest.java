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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.RETURNS_SELF;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ott.OneTimeTokenService;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.ott.OneTimeTokenLoginConfigurer;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.ott.GenerateOneTimeTokenFilter;
import org.springframework.security.web.authentication.ott.GenerateOneTimeTokenRequestResolver;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

/** Unit tests of {@link OttChainCustomizer}. */
@ExtendWith(MockitoExtension.class)
class OttChainCustomizerTest {

    /** Applies the rate limits. */
    @Mock
    private OttRateLimitFilter rateLimitFilter;

    /** Resolves the token requests. */
    @Mock
    private GenerateOneTimeTokenRequestResolver requestResolver;

    /** Delivers the tokens. */
    @Mock
    private OneTimeTokenGenerationSuccessHandler generationSuccessHandler;

    /** Store of the link tokens. */
    @Mock
    private OneTimeTokenService tokenService;

    /** Reads the sign-in post. */
    @Mock
    private AuthenticationConverter authenticationConverter;

    /** Confirms a link. */
    @Mock
    private AuthenticationProvider linkProvider;

    /** Signs in with a code. */
    @Mock
    private AuthenticationProvider codeProvider;

    /** Resumes the interrupted request. */
    @Mock
    private AuthenticationSuccessHandler successHandler;

    /** Sends the browser back after a failure. */
    @Mock
    private AuthenticationFailureHandler failureHandler;

    /** Processes the second-factor post. */
    @Mock
    private OttSecondFactorFilter secondFactorFilter;

    /**
     * Builds the customizer under test.
     *
     * @return the customizer.
     */
    private OttChainCustomizer customizer() {
        return new OttChainCustomizer(rateLimitFilter, requestResolver, generationSuccessHandler, tokenService,
                authenticationConverter, linkProvider, codeProvider, successHandler, failureHandler,
                secondFactorFilter);
    }

    /** The pages are open, the second-factor post is for signed-in users, and the filters and providers are added. */
    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void customize_whenApplied_permitsThePagesAndAddsTheFiltersAndProviders() {
        final var http = mock(HttpSecurity.class);
        final var authorizeCaptor = ArgumentCaptor.<Customizer<
                AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry>>captor();
        when(http.authorizeHttpRequests(authorizeCaptor.capture())).thenReturn(http);
        final var registry = mock(AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry.class);
        final var open = mock(AuthorizeHttpRequestsConfigurer.AuthorizedUrl.class);
        final var signedIn = mock(AuthorizeHttpRequestsConfigurer.AuthorizedUrl.class);
        when(registry.requestMatchers(any(String[].class))).thenReturn(open, signedIn);
        when(open.permitAll()).thenReturn(registry);

        customizer().customize(http);
        authorizeCaptor.getValue().customize(registry);

        verify(registry).requestMatchers("/ott/generate", "/login/ott", "/login/ott/**");
        verify(registry).requestMatchers("/login/second-factor/ott");
        verify(open).permitAll();
        verify(signedIn).authenticated();
        verify(http).addFilterBefore(rateLimitFilter, GenerateOneTimeTokenFilter.class);
        verify(http).addFilterBefore(secondFactorFilter, AuthorizationFilter.class);
        verify(http).authenticationProvider(codeProvider);
        verify(http).with(any(OttChainCustomizer.SessionStrategyConfigurer.class));
    }

    /** The one-time token login is configured with every collaborator. */
    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void customize_whenApplied_configuresTheOneTimeTokenLogin() {
        final var http = mock(HttpSecurity.class);
        when(http.authorizeHttpRequests(any())).thenReturn(http);
        final var captor = ArgumentCaptor.<Customizer<OneTimeTokenLoginConfigurer<HttpSecurity>>>captor();
        when(http.oneTimeTokenLogin(captor.capture())).thenReturn(http);
        final var configurer = mock(OneTimeTokenLoginConfigurer.class, RETURNS_SELF);

        customizer().customize(http);
        captor.getValue().customize(configurer);

        verify(configurer).tokenGeneratingUrl("/ott/generate");
        verify(configurer).loginProcessingUrl("/login/ott");
        verify(configurer).loginPage("/login");
        verify(configurer).showDefaultSubmitPage(false);
        verify(configurer).tokenService(tokenService);
        verify(configurer).generateRequestResolver(requestResolver);
        verify(configurer).tokenGenerationSuccessHandler(generationSuccessHandler);
        verify(configurer).authenticationConverter(authenticationConverter);
        verify(configurer).authenticationProvider(linkProvider);
        verify(configurer).successHandler(successHandler);
        verify(configurer).failureHandler(failureHandler);
    }

    /** The session authentication strategy of the chain is handed to the second-factor filter. */
    @Test
    void configure_whenTheChainHasASessionStrategy_setsItOnTheFilter() {
        final var http = mock(HttpSecurity.class);
        final var strategy = mock(SessionAuthenticationStrategy.class);
        when(http.getSharedObject(SessionAuthenticationStrategy.class)).thenReturn(strategy);

        new OttChainCustomizer.SessionStrategyConfigurer(secondFactorFilter).configure(http);

        verify(secondFactorFilter).setSessionAuthenticationStrategy(strategy);
    }

    /** The filter keeps its own strategy when the chain has none. */
    @Test
    void configure_whenTheChainHasNoSessionStrategy_leavesTheFilterAlone() {
        final var http = mock(HttpSecurity.class);

        new OttChainCustomizer.SessionStrategyConfigurer(secondFactorFilter).configure(http);

        verify(secondFactorFilter, never()).setSessionAuthenticationStrategy(any());
    }
}
