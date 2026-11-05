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

package com.irurueta.authserver.resourceserver.api.web.security;

import com.irurueta.authserver.resourceserver.api.web.OpenApiConfig;
import com.irurueta.authserver.resourceserver.api.web.documents.DocumentController;
import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.util.CollectionUtils;

/**
 * Secures the API: every request except the health endpoint and the OpenAPI document requires a valid bearer token
 * issued by the authorization server for this resource server's audience. Failures answer with the RFC 6750
 * {@code WWW-Authenticate} challenge ({@code invalid_token} / {@code insufficient_scope}). By default the tokens are
 * JWTs; the {@code opaque} profile introspects them instead.
 */
@Configuration(proxyBeanMethods = false)
@EnableMethodSecurity
public class SecurityConfig {

    /** Authority of the scope that allows reading documents. */
    static final String READ_AUTHORITY = "SCOPE_documents.read";

    // tag::resource-server-security[]
    /**
     * Builds the filter chain validating bearer JWTs (the decoder is built from {@code issuer-uri}, and the
     * configured audiences are validated by it).
     *
     * @param http       the HTTP security builder.
     * @param properties the resource server properties.
     * @return the security filter chain.
     * @throws Exception if the chain cannot be built.
     * @throws IllegalStateException if no accepted audience is configured.
     */
    @Bean
    @Profile("!opaque")
    SecurityFilterChain resourceServerFilterChain(final HttpSecurity http,
            final OAuth2ResourceServerProperties properties) throws Exception {
        requireAudiences(properties.getJwt().getAudiences());
        authorize(http);
        http.oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
                .accessDeniedHandler(new BearerTokenAccessDeniedHandler()));
        return http.build();
    }
    // end::resource-server-security[]

    /**
     * Builds the filter chain of the opaque-token variant.
     *
     * @param http        the HTTP security builder.
     * @param introspector introspector that validates the opaque tokens.
     * @return the security filter chain.
     * @throws Exception if the chain cannot be built.
     */
    @Bean
    @Profile("opaque")
    SecurityFilterChain opaqueTokenFilterChain(final HttpSecurity http, final OpaqueTokenIntrospector introspector)
            throws Exception {
        authorize(http);
        http.oauth2ResourceServer(oauth2 -> oauth2
                .opaqueToken(opaque -> opaque.introspector(introspector))
                .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
                .accessDeniedHandler(new BearerTokenAccessDeniedHandler()));
        return http.build();
    }

    /**
     * Builds the introspector of the opaque-token variant. The introspection URI and the client credentials come
     * from the environment (see {@code application-opaque.yml}); no value is ever defaulted.
     *
     * @param properties the resource server properties.
     * @return the introspector.
     * @throws IllegalStateException if no accepted audience is configured.
     */
    @Bean
    @Profile("opaque")
    OpaqueTokenIntrospector opaqueTokenIntrospector(final OAuth2ResourceServerProperties properties) {
        final var audiences = properties.getJwt().getAudiences();
        requireAudiences(audiences);
        final var opaque = properties.getOpaquetoken();
        final var delegate = SpringOpaqueTokenIntrospector.withIntrospectionUri(opaque.getIntrospectionUri())
                .clientId(opaque.getClientId())
                .clientSecret(opaque.getClientSecret())
                .build();
        return new AudienceRolesOpaqueTokenIntrospector(delegate, List.copyOf(audiences));
    }

    // tag::resource-server-converter[]
    /**
     * Maps the {@code scope} claim to {@code SCOPE_*} authorities (the default converter) and the {@code roles}
     * claim to {@code ROLE_*} authorities.
     *
     * @return the converter.
     */
    JwtAuthenticationConverter jwtAuthenticationConverter() {
        final var scopes = new JwtGrantedAuthoritiesConverter();
        final var converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            final var authorities = new ArrayList<GrantedAuthority>(scopes.convert(jwt));
            authorities.addAll(BearerAuthorities.roleAuthorities(
                    jwt.getClaimAsStringList(BearerAuthorities.ROLES_CLAIM)));
            return authorities;
        });
        return converter;
    }
    // end::resource-server-converter[]

    /**
     * Declares which requests are public and which need a scope. Deleting is protected by method security.
     *
     * @param http the HTTP security builder.
     */
    private static void authorize(final HttpSecurity http) {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/actuator/health/**", OpenApiConfig.API_DOCS_PATH + "/**").permitAll()
                .requestMatchers(HttpMethod.GET, DocumentController.PATH).hasAuthority(READ_AUTHORITY)
                .anyRequest().authenticated());
    }

    /**
     * Fails fast when no accepted audience is configured, instead of accepting every token.
     *
     * @param audiences configured audiences.
     * @throws IllegalStateException if there is none.
     */
    private static void requireAudiences(final List<String> audiences) {
        if (CollectionUtils.isEmpty(audiences)) {
            throw new IllegalStateException(
                    "spring.security.oauth2.resourceserver.jwt.audiences must list the accepted audience");
        }
    }
}
