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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.boot.security.oauth2.server.resource.autoconfigure.OAuth2ResourceServerProperties;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

/**
 * Unit tests for {@link SecurityConfig}. The filter chains themselves are exercised end to end by the integration
 * tests of the {@code boot} module.
 */
class SecurityConfigTest {

    /** Lifetime of the test tokens, in seconds. */
    private static final long TTL_SECONDS = 60;

    /** Subject under test. */
    private final SecurityConfig config = new SecurityConfig();

    /** Step-up policy of the tests. */
    private final StepUpProperties stepUpProperties = new StepUpProperties(true, "urn:irurueta:acr:mfa",
            Duration.ofMinutes(5));

    /** Manager under the chains. */
    private final StepUpAuthorizationManager stepUp = config.stepUpAuthorizationManager(stepUpProperties);

    /** Handler under the chains. */
    private final StepUpAccessDeniedHandler handler = config.stepUpAccessDeniedHandler(stepUpProperties);

    /** The step-up beans are built from the policy. */
    @Test
    void stepUpBeans_whenPolicyIsGiven_areCreated() {
        assertNotNull(stepUp);
        assertNotNull(handler);
    }

    /** Scopes and roles both become authorities. */
    @Test
    void jwtAuthenticationConverter_whenTokenHasScopesAndRoles_mapsBoth() {
        final var jwt = Jwt.withTokenValue("token").header("alg", "none").subject("alice")
                .claim("scope", "documents.read documents.delete")
                .claim("roles", List.of("ADMIN"))
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(TTL_SECONDS)).build();

        final var authentication = config.jwtAuthenticationConverter().convert(jwt);

        assertEquals(List.of("SCOPE_documents.read", "SCOPE_documents.delete", "ROLE_ADMIN"),
                authorities(authentication));
    }

    /** A token without roles only has its scopes. */
    @Test
    void jwtAuthenticationConverter_whenTokenHasNoRoles_mapsOnlyScopes() {
        final var jwt = Jwt.withTokenValue("token").header("alg", "none").subject("alice")
                .claim("scope", "documents.read")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(TTL_SECONDS)).build();

        final var authentication = config.jwtAuthenticationConverter().convert(jwt);

        assertEquals(List.of("SCOPE_documents.read"), authorities(authentication));
    }

    /** The JWT chain refuses to start without an accepted audience. */
    @Test
    void resourceServerFilterChain_whenNoAudienceIsConfigured_failsFast() {
        final var http = mock(HttpSecurity.class);
        final var properties = new OAuth2ResourceServerProperties();

        assertThrows(IllegalStateException.class,
                () -> config.resourceServerFilterChain(http, properties, stepUp, handler));
    }

    /** The opaque variant refuses to start without an accepted audience. */
    @Test
    void opaqueTokenIntrospector_whenNoAudienceIsConfigured_failsFast() {
        final var properties = new OAuth2ResourceServerProperties();

        assertThrows(IllegalStateException.class, () -> config.opaqueTokenIntrospector(properties));
    }

    /** The opaque introspector is built from the configured properties. */
    @Test
    void opaqueTokenIntrospector_whenAudienceIsConfigured_decoratesTheIntrospector() {
        final var properties = new OAuth2ResourceServerProperties();
        properties.getJwt().setAudiences(List.of("resource-server"));
        properties.getOpaquetoken().setIntrospectionUri("http://localhost:9000/oauth2/introspect");
        properties.getOpaquetoken().setClientId("introspector");
        properties.getOpaquetoken().setClientSecret(String.join("-", "a", "b"));

        final OpaqueTokenIntrospector introspector = config.opaqueTokenIntrospector(properties);

        assertInstanceOf(AudienceRolesOpaqueTokenIntrospector.class, introspector);
    }

    /**
     * Lists the authorities of an authentication, leaving out the {@code FACTOR_*} ones that Spring Security adds.
     *
     * @param authentication the authentication.
     * @return the authority names.
     */
    private static List<String> authorities(final AbstractAuthenticationToken authentication) {
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(name -> !name.startsWith("FACTOR_"))
                .toList();
    }
}
