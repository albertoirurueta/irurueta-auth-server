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

package com.irurueta.authserver.bff.api.web.security;

import com.irurueta.authserver.bff.api.web.login.ReturnToAuthenticationSuccessHandler;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;

/**
 * Signs users in with OAuth2 / OpenID Connect login and out with the RP-initiated logout of the authorization server.
 * API calls from the SPA get a 401 instead of a redirect, and every state-changing request must carry the CSRF token
 * the SPA reads from the {@code XSRF-TOKEN} cookie. The tokens of the user stay in the HTTP session (persisted by
 * Spring Session JDBC), never in the browser.
 */
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    /** Content security policy of the BFF: same-origin resources only (so {@code script-src 'self'}), no framing. */
    static final String CONTENT_SECURITY_POLICY = "default-src 'self'; frame-ancestors 'none'";

    /** Page the browser is sent to when the sign-in fails (for example, the user denied the consent). */
    static final String SIGN_IN_FAILURE_URL = "/?error=signin";

    /** Path of the logout, answered by Spring Security's logout filter (only to {@code POST}). */
    static final String LOGOUT_PATH = "/bff/logout";

    // tag::bff-security[]
    /**
     * Builds the BFF filter chain.
     *
     * @param http                 the HTTP security builder.
     * @param clientRepository     the registered OAuth2 clients.
     * @param loginSuccessHandler  sends the browser back to the {@code returnTo} of the login once signed in.
     * @param logoutSuccessHandler redirects the browser to the RP-initiated logout of the authorization server.
     * @return the security filter chain.
     * @throws Exception if the chain cannot be built.
     */
    @Bean
    SecurityFilterChain bffFilterChain(final HttpSecurity http, final ClientRegistrationRepository clientRepository,
            final ReturnToAuthenticationSuccessHandler loginSuccessHandler,
            final OidcClientInitiatedLogoutSuccessHandler logoutSuccessHandler) throws Exception {
        final var resolver = new DefaultOAuth2AuthorizationRequestResolver(clientRepository, "/oauth2/authorization");
        // The auth server requires PKCE; Spring only enables it by default for public clients.
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());

        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/", "/index.html", "/favicon.ico", "/assets/**", "/static/**", "/error",
                                "/bff/login", "/actuator/health/**").permitAll()
                        .anyRequest().authenticated())
                // The XSRF-TOKEN cookie is readable by the script (not HttpOnly) and the raw token is accepted from
                // the X-XSRF-TOKEN header or, for the sign-out form, from the _csrf parameter. The plain handler, not
                // csrf.spa()'s XOR one: masking against BREACH protects a token rendered in a compressed response body,
                // and the BFF never renders it in a body, only in the cookie; the XOR handler would also reject the
                // raw cookie value the sign-out form posts.
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler()))
                // The SPA is made of same-origin files only: no inline script, no third-party content, no framing.
                .headers(headers -> headers.contentSecurityPolicy(
                        csp -> csp.policyDirectives(CONTENT_SECURITY_POLICY)))
                .addFilterAfter(new CsrfCookieFilter(), CsrfFilter.class)
                .exceptionHandling(ex -> ex.defaultAuthenticationEntryPointFor(
                        new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                        new OrRequestMatcher(PathPatternRequestMatcher.withDefaults().matcher("/bff/**"),
                                PathPatternRequestMatcher.withDefaults().matcher("/api/**"))))
                .oauth2Login(login -> login
                        .authorizationEndpoint(endpoint -> endpoint.authorizationRequestResolver(resolver))
                        // A refused consent or any other failed sign-in lands on the SPA, which tells the user.
                        // A handler rather than failureUrl: that would make the generated login page answer it.
                        .failureHandler(new SimpleUrlAuthenticationFailureHandler(SIGN_IN_FAILURE_URL))
                        // Back to the returnTo validated by GET /bff/login, never to a request saved elsewhere.
                        .successHandler(loginSuccessHandler))
                // tag::bff-logout[]
                // POST /bff/logout (CSRF protected) runs the logout handlers (the XSRF-TOKEN cookie is cleared, the
                // security context too, and the session is invalidated), then the success handler answers 302 to the
                // end_session_endpoint of the authorization server: the browser follows it as a top-level navigation,
                // so the id_token_hint it carries never reaches a script.
                .logout(logout -> logout
                        .logoutRequestMatcher(PathPatternRequestMatcher.withDefaults()
                                .matcher(HttpMethod.POST, LOGOUT_PATH))
                        .logoutSuccessHandler(logoutSuccessHandler));
                // end::bff-logout[]
        return http.build();
    }
    // end::bff-security[]

    // tag::bff-authorized-client[]
    /**
     * Keeps the authorized clients (the tokens of the signed-in user) in the HTTP session, which Spring Session JDBC
     * persists, so no table of its own is needed and the tokens never reach the browser.
     *
     * @return the repository of authorized clients.
     */
    @Bean
    OAuth2AuthorizedClientRepository authorizedClientRepository() {
        return new HttpSessionOAuth2AuthorizedClientRepository();
    }

    /**
     * Builds the manager that obtains the access token of the signed-in user and renews it with its refresh token when
     * it expires.
     *
     * @param clientRepository           the registered OAuth2 clients.
     * @param authorizedClientRepository where the authorized clients are kept.
     * @return the authorized client manager, with the {@code authorization_code} and {@code refresh_token} providers.
     */
    @Bean
    OAuth2AuthorizedClientManager authorizedClientManager(final ClientRegistrationRepository clientRepository,
            final OAuth2AuthorizedClientRepository authorizedClientRepository) {
        final var manager = new DefaultOAuth2AuthorizedClientManager(clientRepository, authorizedClientRepository);
        manager.setAuthorizedClientProvider(OAuth2AuthorizedClientProviderBuilder.builder()
                .authorizationCode()
                .refreshToken()
                .build());
        return manager;
    }
    // end::bff-authorized-client[]
}
