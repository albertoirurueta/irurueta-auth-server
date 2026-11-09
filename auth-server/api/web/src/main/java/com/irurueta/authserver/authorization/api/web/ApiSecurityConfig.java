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

import com.irurueta.authserver.authorization.application.clients.DefaultClientDefinitions;
import com.irurueta.authserver.authorization.domain.account.SignedTokenService;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Security filter chain of the REST API under {@code /api/**}: stateless, bearer tokens issued by this server and
 * validated by a decoder of its own (never the framework-wide one, which also serves the UserInfo endpoint). That
 * decoder only accepts a token that this server signed, whose issuer is this server, whose timestamps are valid,
 * whose {@code aud} lists the API audience ({@code authserver.api.audience}, default {@code auth-server}) and that
 * does not carry the {@code purpose} claim of the account tokens (an e-mail verification JWT is never a bearer
 * token). Authentication and access failures are answered as described by RFC 6750
 * ({@code WWW-Authenticate: Bearer ...}).
 */
@Configuration(proxyBeanMethods = false)
public class ApiSecurityConfig {

    /** Path pattern of the REST API. */
    public static final String API_PATTERN = "/api/**";

    // tag::api-admin-scope[]
    /** Path pattern of the administration API. */
    public static final String ADMIN_PATTERN = "/api/admin/**";

    /** Scope that grants access to the administration API; a role alone never does. */
    public static final String ADMIN_SCOPE_AUTHORITY = "SCOPE_admin";
    // end::api-admin-scope[]

    /** Property that holds the audience a token must carry to call the API. */
    public static final String API_AUDIENCE_PROPERTY = "authserver.api.audience";

    /** Prefix of the authorities derived from roles. */
    private static final String ROLE_PREFIX = "ROLE_";

    /** Name of the claim that holds the roles. */
    private static final String ROLES_CLAIM = "roles";

    // tag::api-security[]
    /**
     * Creates the chain of the REST API.
     *
     * @param http      security builder.
     * @param jwkSource the published keys of this server.
     * @param issuer    issuer of this server ({@code spring.security.oauth2.authorizationserver.issuer}).
     * @param audience  audience the API requires ({@code authserver.api.audience}).
     * @return the API filter chain.
     * @throws Exception if the chain cannot be built.
     */
    @Bean
    @Order(0)
    public SecurityFilterChain apiSecurityFilterChain(
            final HttpSecurity http, final JWKSource<SecurityContext> jwkSource,
            @Value("${spring.security.oauth2.authorizationserver.issuer}") final String issuer,
            @Value("${" + API_AUDIENCE_PROPERTY + ":" + DefaultClientDefinitions.DEFAULT_API_AUDIENCE + "}")
            final String audience) throws Exception {
        http
                .securityMatcher(API_PATTERN)
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(HttpMethod.POST, "/api/account/register", "/api/account/password/reset",
                                "/api/account/password/reset-request")
                        .permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/account/verify").permitAll()
                        .requestMatchers(ADMIN_PATTERN).hasAuthority(ADMIN_SCOPE_AUTHORITY)
                        .anyRequest().authenticated())
                .oauth2ResourceServer(resource -> resource
                        .jwt(jwt -> jwt.decoder(apiJwtDecoder(jwkSource, issuer, audience))
                                .jwtAuthenticationConverter(apiJwtAuthenticationConverter())));
        return http.build();
    }

    /**
     * Creates the decoder of the API's bearer tokens: signature against the published keys, issuer, timestamps,
     * audience, and no {@code purpose} claim.
     *
     * @param jwkSource the published keys of this server.
     * @param issuer    issuer every token must have.
     * @param audience  audience every token must list.
     * @return the decoder.
     */
    static JwtDecoder apiJwtDecoder(final JWKSource<SecurityContext> jwkSource, final String issuer,
                                    final String audience) {
        final var decoder = NimbusJwtDecoder.withJwkSource(jwkSource).jwsAlgorithm(SignatureAlgorithm.RS256).build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(List.<OAuth2TokenValidator<Jwt>>of(
                JwtValidators.createDefaultWithIssuer(issuer),
                // tag::api-admin-scope[]
                new JwtClaimValidator<List<String>>(JwtClaimNames.AUD,
                        audiences -> audiences != null && audiences.contains(audience)),
                // end::api-admin-scope[]
                ApiSecurityConfig::rejectPurposeBoundToken)));
        return decoder;
    }

    /**
     * Rejects a purpose-bound account token (such as an e-mail verification JWT): it is signed by this server but
     * never meant as a bearer token.
     *
     * @param jwt the token.
     * @return a failure when the token carries the {@code purpose} claim, a success otherwise.
     */
    private static OAuth2TokenValidatorResult rejectPurposeBoundToken(final Jwt jwt) {
        if (jwt.hasClaim(SignedTokenService.PURPOSE_CLAIM)) {
            return OAuth2TokenValidatorResult.failure(new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN,
                    "A purpose-bound account token is not a bearer token", null));
        }
        return OAuth2TokenValidatorResult.success();
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
