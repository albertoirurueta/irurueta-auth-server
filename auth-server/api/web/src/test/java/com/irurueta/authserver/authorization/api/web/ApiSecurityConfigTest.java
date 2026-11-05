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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Unit tests of the token converter of {@link ApiSecurityConfig}.
 */
class ApiSecurityConfigTest {

    /** Lifetime in seconds of the test tokens. */
    private static final long TTL_SECONDS = 60;

    /**
     * Verifies that scopes become {@code SCOPE_*} authorities.
     */
    @Test
    void apiJwtAuthenticationConverter_whenTokenHasScopes_mapsThemToScopeAuthorities() {
        final var authorities = convert(Jwt.withTokenValue("t").header("alg", "none")
                .claim("scope", "read admin").issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(TTL_SECONDS)).build());

        assertEquals(Set.of("SCOPE_read", "SCOPE_admin"), authorities);
    }

    /**
     * Verifies that roles become {@code ROLE_*} authorities, without doubling an existing prefix.
     */
    @Test
    void apiJwtAuthenticationConverter_whenTokenHasRoles_mapsThemToRoleAuthorities() {
        final var authorities = convert(Jwt.withTokenValue("t").header("alg", "none")
                .claim("roles", List.of("USER", "ROLE_ADMIN")).issuedAt(Instant.now())
                .expiresAt(Instant.now().plusSeconds(TTL_SECONDS)).build());

        assertEquals(Set.of("ROLE_USER", "ROLE_ADMIN"), authorities);
    }

    /**
     * Verifies that a token without scopes and roles has no authorities.
     */
    @Test
    void apiJwtAuthenticationConverter_whenTokenHasNoScopesNorRoles_hasNoAuthorities() {
        final var authorities = convert(Jwt.withTokenValue("t").header("alg", "none").claim("sub", "u")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(TTL_SECONDS)).build());

        assertEquals(Set.of(), authorities);
    }

    /**
     * Converts a token and returns the names of its scope and role authorities; the framework's own
     * {@code FACTOR_*} authority, which records how the caller authenticated, is left out.
     *
     * @param jwt token to convert.
     * @return authority names.
     */
    private static Set<String> convert(final Jwt jwt) {
        final var converter = new ApiSecurityConfig().apiJwtAuthenticationConverter();
        final var authentication = converter.convert(jwt);
        assertNotNull(authentication);
        return authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .filter(name -> !name.startsWith("FACTOR_"))
                .collect(Collectors.toSet());
    }
}
