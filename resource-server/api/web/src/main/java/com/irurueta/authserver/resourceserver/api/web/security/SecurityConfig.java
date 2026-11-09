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
import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
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
@EnableConfigurationProperties(StepUpProperties.class)
public class SecurityConfig {

    /** Authority of the scope that allows reading documents. */
    static final String READ_AUTHORITY = "SCOPE_documents.read";

    /** Authority of the scope that allows deleting documents. */
    static final String DELETE_AUTHORITY = "SCOPE_documents.delete";

    /** Path pattern of a single document. */
    static final String DOCUMENT_PATH = DocumentController.PATH + "/*";

    // tag::resource-server-security[]
    /**
     * Builds the filter chain validating bearer JWTs (the decoder is built from {@code issuer-uri}, and the
     * configured audiences are validated by it).
     *
     * @param http       the HTTP security builder.
     * @param properties the resource server properties.
     * @param stepUp     requires a recent strong authentication to delete.
     * @param accessDeniedHandler answers the denials, including the step-up challenge.
     * @return the security filter chain.
     * @throws Exception if the chain cannot be built.
     * @throws IllegalStateException if no accepted audience is configured.
     */
    @Bean
    @Profile("!opaque")
    SecurityFilterChain resourceServerFilterChain(final HttpSecurity http,
            final OAuth2ResourceServerProperties properties, final StepUpAuthorizationManager stepUp,
            final StepUpAccessDeniedHandler accessDeniedHandler) throws Exception {
        requireAudiences(properties.getJwt().getAudiences());
        authorize(http, stepUp);
        http.oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                // tag::resource-server-bound-tokens[]
                // DPoP (RFC 9449): "Authorization: DPoP <token>" plus a proof; the framework already refuses a
                // token whose cnf holds jkt when it arrives as Bearer. A cnf.x5t#S256 token is checked against the
                // TLS client certificate by the validator of the decoder Boot builds (no JwtDecoder bean here).
                .dPoP(Customizer.withDefaults())
                // end::resource-server-bound-tokens[]
                .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
                .accessDeniedHandler(accessDeniedHandler));
        return http.build();
    }
    // end::resource-server-security[]

    /**
     * Builds the filter chain of the opaque-token variant.
     *
     * @param http        the HTTP security builder.
     * @param introspector introspector that validates the opaque tokens.
     * @param stepUp       requires a recent strong authentication to delete.
     * @param accessDeniedHandler answers the denials, including the step-up challenge.
     * @return the security filter chain.
     * @throws Exception if the chain cannot be built.
     */
    @Bean
    @Profile("opaque")
    SecurityFilterChain opaqueTokenFilterChain(final HttpSecurity http, final OpaqueTokenIntrospector introspector,
            final StepUpAuthorizationManager stepUp, final StepUpAccessDeniedHandler accessDeniedHandler)
            throws Exception {
        authorize(http, stepUp);
        http.oauth2ResourceServer(oauth2 -> oauth2
                .opaqueToken(opaque -> opaque.introspector(introspector))
                .authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
                .accessDeniedHandler(accessDeniedHandler));
        return http.build();
    }

    // tag::resource-server-step-up-beans[]
    /**
     * Builds the manager that requires a recent strong authentication to delete a document.
     *
     * @param properties the step-up policy.
     * @return the manager.
     */
    @Bean
    StepUpAuthorizationManager stepUpAuthorizationManager(final StepUpProperties properties) {
        return new StepUpAuthorizationManager(DELETE_AUTHORITY, properties, Clock.systemUTC());
    }

    /**
     * Builds the handler that answers the step-up requirement with the RFC 9470 challenge and every other denial
     * with the RFC 6750 one.
     *
     * @param properties the step-up policy.
     * @return the handler.
     */
    @Bean
    StepUpAccessDeniedHandler stepUpAccessDeniedHandler(final StepUpProperties properties) {
        return new StepUpAccessDeniedHandler(new BearerTokenAccessDeniedHandler(), properties);
    }
    // end::resource-server-step-up-beans[]

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
     * Declares which requests are public and which need a scope. Deleting also needs a recent strong
     * authentication (RFC 9470) and is protected by method security as well.
     *
     * @param http   the HTTP security builder.
     * @param stepUp requires a recent strong authentication to delete.
     */
    private static void authorize(final HttpSecurity http, final StepUpAuthorizationManager stepUp) {
        // tag::resource-server-authorize[]
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/actuator/health/**", OpenApiConfig.API_DOCS_PATH + "/**").permitAll()
                .requestMatchers(HttpMethod.GET, DocumentController.PATH).hasAuthority(READ_AUTHORITY)
                .requestMatchers(HttpMethod.DELETE, DOCUMENT_PATH).access(stepUp)
                .anyRequest().authenticated());
        // end::resource-server-authorize[]
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
