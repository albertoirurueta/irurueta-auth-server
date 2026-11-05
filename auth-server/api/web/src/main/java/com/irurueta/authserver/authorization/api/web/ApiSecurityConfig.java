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

package com.irurueta.authserver.authorization.api.web;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security filter chain of the REST API under {@code /api/**}: stateless, bearer tokens issued by this server and
 * validated with its own {@link org.springframework.security.oauth2.jwt.JwtDecoder}. Authentication and access
 * failures are answered as described by RFC 6750 ({@code WWW-Authenticate: Bearer ...}).
 */
@Configuration(proxyBeanMethods = false)
public class ApiSecurityConfig {

    /** Path pattern of the REST API. */
    public static final String API_PATTERN = "/api/**";

    /** Path pattern of the administration API. */
    public static final String ADMIN_PATTERN = "/api/admin/**";

    /** Scope that grants access to the administration API. */
    public static final String ADMIN_SCOPE_AUTHORITY = "SCOPE_admin";

    /** Role that grants access to the administration API. */
    public static final String ADMIN_ROLE_AUTHORITY = "ROLE_ADMIN";

    /** Prefix of the authorities derived from roles. */
    private static final String ROLE_PREFIX = "ROLE_";

    /** Name of the claim that holds the roles. */
    private static final String ROLES_CLAIM = "roles";

    // tag::api-security[]
    /**
     * Creates the chain of the REST API.
     *
     * @param http security builder.
     * @return the API filter chain.
     * @throws Exception if the chain cannot be built.
     */
    @Bean
    @Order(0)
    public SecurityFilterChain apiSecurityFilterChain(final HttpSecurity http) throws Exception {
        http
                .securityMatcher(API_PATTERN)
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.POST, "/api/account/register", "/api/account/password/reset",
                                "/api/account/password/reset-request")
                        .permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/account/verify").permitAll()
                        .requestMatchers(ADMIN_PATTERN).hasAnyAuthority(ADMIN_SCOPE_AUTHORITY, ADMIN_ROLE_AUTHORITY)
                        .anyRequest().authenticated())
                .oauth2ResourceServer(resource -> resource
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(apiJwtAuthenticationConverter())));
        return http.build();
    }

    /**
     * Creates the converter that maps the {@code scope} claim to {@code SCOPE_*} authorities and the {@code roles}
     * claim to {@code ROLE_*} authorities.
     *
     * @return the converter.
     */
    JwtAuthenticationConverter apiJwtAuthenticationConverter() {
        final var scopes = new JwtGrantedAuthoritiesConverter();
        final var converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            final var authorities = new ArrayList<GrantedAuthority>(scopes.convert(jwt));
            authorities.addAll(roleAuthorities(jwt));
            return authorities;
        });
        return converter;
    }
    // end::api-security[]

    /**
     * Maps the roles of a token to authorities, adding the {@code ROLE_} prefix when it is missing.
     *
     * @param jwt token to read.
     * @return the role authorities, empty when the token has no roles.
     */
    private static Collection<GrantedAuthority> roleAuthorities(final Jwt jwt) {
        final var roles = jwt.getClaimAsStringList(ROLES_CLAIM);
        if (roles == null) {
            return List.of();
        }
        return roles.stream()
                .map(role -> role.startsWith(ROLE_PREFIX) ? role : ROLE_PREFIX + role)
                .<GrantedAuthority>map(SimpleGrantedAuthority::new)
                .toList();
    }
}
