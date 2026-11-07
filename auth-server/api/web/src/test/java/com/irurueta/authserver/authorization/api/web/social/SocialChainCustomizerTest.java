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

package com.irurueta.authserver.authorization.api.web.social;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
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
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Unit tests of {@link SocialChainCustomizer}.
 */
@ExtendWith(MockitoExtension.class)
class SocialChainCustomizerTest {

    /** Registrations of the configured providers. */
    @Mock
    private ClientRegistrationRepository clientRegistrationRepository;

    /** Resolves the account of an OpenID Connect sign-in. */
    @Mock
    private FederatedOidcUserService oidcUserService;

    /** Resolves the account of an OAuth 2.0 sign-in. */
    @Mock
    private FederatedOAuth2UserService oauth2UserService;

    /** Grants the federated factor. */
    @Mock
    private AuthenticationSuccessHandler successHandler;

    /** Saves the security context. */
    @Mock
    private SecurityContextRepository securityContextRepository;

    /** Exchanges the authorization code. */
    @Mock
    private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> tokenResponseClient;

    /** Builds the authorization requests. */
    @Mock
    private OAuth2AuthorizationRequestResolver authorizationRequestResolver;

    /**
     * Verifies that the endpoints of the framework are public.
     */
    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void customize_whenApplied_permitsTheEndpointsOfTheFramework() {
        final var http = mock(HttpSecurity.class, RETURNS_SELF);
        final var captor = ArgumentCaptor.<Customizer<
                AuthorizeHttpRequestsConfigurer<HttpSecurity>.AuthorizationManagerRequestMatcherRegistry>>captor();
        when(http.authorizeHttpRequests(captor.capture())).thenReturn(http);
        final var registry = mock(AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry.class);
        final var open = mock(AuthorizeHttpRequestsConfigurer.AuthorizedUrl.class);
        when(registry.requestMatchers("/oauth2/authorization/**", "/login/oauth2/code/*")).thenReturn(open);

        customizer(false).customize(http);
        captor.getValue().customize(registry);

        verify(open).permitAll();
    }

    /**
     * Verifies that without Apple the CSRF protection is left alone.
     */
    @Test
    void customize_whenAppleIsNotConfigured_doesNotTouchCsrf() {
        final var http = mock(HttpSecurity.class, RETURNS_SELF);

        customizer(false).customize(http);

        verify(http, never()).csrf(any());
    }

    /**
     * Verifies that with Apple only the post to Apple's callback is exempt from CSRF protection.
     */
    @Test
    @SuppressWarnings("unchecked")
    void customize_whenAppleIsConfigured_exemptsOnlyThePostToAppleCallback() {
        final var http = mock(HttpSecurity.class, RETURNS_SELF);
        final var captor = ArgumentCaptor.<Customizer<CsrfConfigurer<HttpSecurity>>>captor();
        when(http.csrf(captor.capture())).thenReturn(http);
        final var csrf = mock(CsrfConfigurer.class, RETURNS_SELF);

        customizer(true).customize(http);
        captor.getValue().customize(csrf);

        final var matcherCaptor = ArgumentCaptor.<RequestMatcher>captor();
        verify(csrf).ignoringRequestMatchers(matcherCaptor.capture());
        final var matcher = matcherCaptor.getValue();
        assertTrue(matcher.matches(new MockHttpServletRequest("POST", "/login/oauth2/code/apple")));
        assertFalse(matcher.matches(new MockHttpServletRequest("GET", "/login/oauth2/code/apple")));
        assertFalse(matcher.matches(new MockHttpServletRequest("POST", "/login/oauth2/code/google")));
    }

    /**
     * Verifies the login: the registrations, the server's own login page, the context repository, the success handler
     * and the endpoints with the token client, the request resolver and both user services.
     */
    @Test
    @SuppressWarnings({"unchecked", "rawtypes"})
    void customize_whenApplied_configuresTheOAuth2Login() {
        final var http = mock(HttpSecurity.class, RETURNS_SELF);
        final var captor = ArgumentCaptor.<Customizer<OAuth2LoginConfigurer<HttpSecurity>>>captor();
        when(http.oauth2Login(captor.capture())).thenReturn(http);
        final var login = mock(OAuth2LoginConfigurer.class, RETURNS_SELF);
        final var authorization = ArgumentCaptor.<Customizer>captor();
        final var token = ArgumentCaptor.<Customizer>captor();
        final var userInfo = ArgumentCaptor.<Customizer>captor();
        when(login.authorizationEndpoint(authorization.capture())).thenReturn(login);
        when(login.tokenEndpoint(token.capture())).thenReturn(login);
        when(login.userInfoEndpoint(userInfo.capture())).thenReturn(login);

        customizer(false).customize(http);
        captor.getValue().customize(login);

        verify(login).clientRegistrationRepository(clientRegistrationRepository);
        verify(login).loginPage("/login");
        verify(login).securityContextRepository(securityContextRepository);
        verify(login).successHandler(successHandler);
        final var authorizationConfig = mock(OAuth2LoginConfigurer.AuthorizationEndpointConfig.class, RETURNS_SELF);
        authorization.getValue().customize(authorizationConfig);
        verify(authorizationConfig).authorizationRequestResolver(authorizationRequestResolver);
        final var tokenConfig = mock(OAuth2LoginConfigurer.TokenEndpointConfig.class, RETURNS_SELF);
        token.getValue().customize(tokenConfig);
        verify(tokenConfig).accessTokenResponseClient(tokenResponseClient);
        final var userInfoConfig = mock(OAuth2LoginConfigurer.UserInfoEndpointConfig.class, RETURNS_SELF);
        userInfo.getValue().customize(userInfoConfig);
        verify(userInfoConfig).userService(oauth2UserService);
        verify(userInfoConfig).oidcUserService(oidcUserService);
    }

    /**
     * Builds the customizer under test.
     *
     * @param apple whether Apple is configured.
     * @return the customizer.
     */
    private SocialChainCustomizer customizer(final boolean apple) {
        return new SocialChainCustomizer(clientRegistrationRepository, oidcUserService, oauth2UserService,
                successHandler, securityContextRepository, tokenResponseClient, authorizationRequestResolver, apple);
    }
}
