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

import static com.irurueta.authserver.authorization.api.web.login.LoginController.LOGIN_PATH;

import com.irurueta.authserver.authorization.api.web.login.LoginChainCustomizer;
import com.irurueta.authserver.authorization.domain.social.IdentityProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

// tag::social-chain[]
/**
 * Customizes the login/UI chain with the sign-in with external providers: {@code http.oauth2Login(...)} with the
 * client registrations of the configured providers, the user services that resolve the local account, the success
 * handler that grants the federated factor and, for Apple, the signed client secret and the form post callback.
 *
 * <p>The endpoints of the framework ({@code /oauth2/authorization/*} starts a sign-in, {@code /login/oauth2/code/*}
 * receives the provider's answer) are public. The login page is the server's own, so the provider's page is never
 * chosen automatically even when one provider is configured. Apple posts its answer to the callback from another site,
 * so that one callback is exempt from CSRF protection (the {@code state} of the authorization request protects it) and
 * the session cookie must be sent on a cross-site post (see the documentation of the social login). The same
 * endpoints serve the explicit link flow of the identities page: the success and failure handlers tell a link apart.
 */
@RequiredArgsConstructor
public class SocialChainCustomizer implements LoginChainCustomizer {

    /** Order of the customizer: after the phone page one. */
    public static final int ORDER = 5;

    /** Pattern of the endpoints that start a sign-in. */
    static final String AUTHORIZATION_PATTERN = "/oauth2/authorization/**";

    /** Pattern of the endpoints that receive the provider's answer. */
    static final String CALLBACK_PATTERN = "/login/oauth2/code/*";

    /** Registrations of the configured providers. */
    private final ClientRegistrationRepository clientRegistrationRepository;

    /** Resolves the account of an OpenID Connect sign-in. */
    private final FederatedOidcUserService oidcUserService;

    /** Resolves the account of an OAuth 2.0 sign-in. */
    private final FederatedOAuth2UserService oauth2UserService;

    /** Grants the federated factor and resumes the saved request, or completes a link. */
    private final AuthenticationSuccessHandler successHandler;

    /** Sends a refused link back to the identities page, any other failure to the login page. */
    private final AuthenticationFailureHandler failureHandler;

    /** Saves the security context of the sign-in. */
    private final SecurityContextRepository securityContextRepository;

    /** Exchanges the authorization code for tokens. */
    private final OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> tokenResponseClient;

    /** Builds the authorization requests. */
    private final OAuth2AuthorizationRequestResolver authorizationRequestResolver;

    /** Whether Apple is configured, which posts its answer to the callback. */
    private final boolean appleEnabled;

    /**
     * Customizes the login/UI chain.
     *
     * @param http security builder of the chain.
     */
    @Override
    public void customize(final HttpSecurity http) {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(AUTHORIZATION_PATTERN, CALLBACK_PATTERN).permitAll());
        if (appleEnabled) {
            http.csrf(csrf -> csrf.ignoringRequestMatchers(PathPatternRequestMatcher.withDefaults()
                    .matcher(HttpMethod.POST, "/login/oauth2/code/" + IdentityProvider.APPLE.id())));
        }
        http.oauth2Login(login -> login
                .clientRegistrationRepository(clientRegistrationRepository)
                .loginPage(LOGIN_PATH)
                .securityContextRepository(securityContextRepository)
                .successHandler(successHandler)
                .failureHandler(failureHandler)
                .authorizationEndpoint(endpoint -> endpoint.authorizationRequestResolver(authorizationRequestResolver))
                .tokenEndpoint(endpoint -> endpoint.accessTokenResponseClient(tokenResponseClient))
                .userInfoEndpoint(endpoint -> endpoint
                        .userService(oauth2UserService)
                        .oidcUserService(oidcUserService)));
    }
}
// end::social-chain[]
