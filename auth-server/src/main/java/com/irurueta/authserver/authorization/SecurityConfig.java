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

package com.irurueta.authserver.authorization;

import com.irurueta.authserver.authorization.login.LoginChainCustomizer;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

/**
 * Security filter chains of the authorization server: the protocol endpoints chain and the login/UI chain.
 */
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    /** Path of the login page. */
    static final String LOGIN_PATH = "/login";

    // tag::security-chains[]
    /**
     * Creates the chain of the OAuth 2.1 and OpenID Connect protocol endpoints.
     *
     * @param http security builder.
     * @return the protocol filter chain.
     * @throws Exception if the chain cannot be built.
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(final HttpSecurity http) throws Exception {
        http
                .oauth2AuthorizationServer(server -> {
                    http.securityMatcher(server.getEndpointsMatcher());
                    server.oidc(Customizer.withDefaults());
                })
                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(LOGIN_PATH)));
        return http.build();
    }

    /**
     * Creates the chain of the login page and the rest of the user interface.
     *
     * @param http        security builder.
     * @param customizers login method customizers, applied in order.
     * @return the login/UI filter chain.
     * @throws Exception if the chain cannot be built.
     */
    @Bean
    @Order(2)
    public SecurityFilterChain loginSecurityFilterChain(
            final HttpSecurity http, final ObjectProvider<LoginChainCustomizer> customizers) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(LOGIN_PATH, "/error", "/actuator/health/**", "/v3/api-docs/**").permitAll()
                        .anyRequest().authenticated())
                .formLogin(form -> form.loginPage(LOGIN_PATH).permitAll());
        for (final var customizer : customizers.orderedStream().toList()) {
            customizer.customize(http);
        }
        return http.build();
    }
    // end::security-chains[]
}
