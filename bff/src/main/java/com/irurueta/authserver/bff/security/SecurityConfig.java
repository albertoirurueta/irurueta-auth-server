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

package com.irurueta.authserver.bff.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

/**
 * Signs users in with OAuth2 / OpenID Connect login. API calls from the SPA get a 401 instead of a redirect.
 */
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    // tag::bff-security[]
    /**
     * Builds the BFF filter chain.
     *
     * @param http             the HTTP security builder.
     * @param clientRepository the registered OAuth2 clients.
     * @return the security filter chain.
     * @throws Exception if the chain cannot be built.
     */
    @Bean
    SecurityFilterChain bffFilterChain(final HttpSecurity http, final ClientRegistrationRepository clientRepository)
            throws Exception {
        final var resolver = new DefaultOAuth2AuthorizationRequestResolver(clientRepository, "/oauth2/authorization");
        // The auth server requires PKCE; Spring only enables it by default for public clients.
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());

        http.authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/actuator/health/**").permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(ex -> ex.defaultAuthenticationEntryPointFor(
                        new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED),
                        PathPatternRequestMatcher.withDefaults().matcher("/bff/**")))
                .oauth2Login(login -> login.authorizationEndpoint(
                        endpoint -> endpoint.authorizationRequestResolver(resolver)));
        return http.build();
    }
    // end::bff-security[]
}
