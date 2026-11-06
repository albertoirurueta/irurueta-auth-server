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

package com.irurueta.authserver.authorization.api.web.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.FactorGrantedAuthority;

/**
 * Unit tests of {@link FactorGrantor}.
 */
class FactorGrantorTest {

    /** Authority of the factor. */
    private static final String AUTHORITY = "FACTOR_TOTP";

    /** The instant of the clock. */
    private static final Instant NOW = Instant.parse("2026-01-01T10:00:00Z");

    /** Number of authorities the original authentication holds. */
    private static final int ORIGINAL_AUTHORITIES = 2;

    /** Grantor under test. */
    private final FactorGrantor grantor = new FactorGrantor(Clock.fixed(NOW, ZoneOffset.UTC));

    /**
     * Verifies that a new authentication keeps the authorities and adds the factor stamped with the current time.
     */
    @Test
    void grant_whenFactorIsMissing_returnsNewAuthenticationWithTheFactor() {
        final var original = UsernamePasswordAuthenticationToken.authenticated("alice", "secret",
                AuthorityUtils.createAuthorityList("ROLE_USER", FactorGrantedAuthority.PASSWORD_AUTHORITY));

        final var result = grantor.grant(original, AUTHORITY);

        assertEquals("alice", result.getPrincipal());
        assertTrue(result.isAuthenticated());
        assertEquals(ORIGINAL_AUTHORITIES + 1, result.getAuthorities().size());
        assertTrue(result.getAuthorities().stream().anyMatch(a -> "ROLE_USER".equals(a.getAuthority())));
        final var factor = result.getAuthorities().stream()
                .filter(FactorGrantedAuthority.class::isInstance)
                .map(FactorGrantedAuthority.class::cast)
                .filter(a -> AUTHORITY.equals(a.getAuthority()))
                .findFirst().orElseThrow();
        assertEquals(NOW, factor.getIssuedAt());
        assertEquals(ORIGINAL_AUTHORITIES, original.getAuthorities().size());
    }

    /**
     * Verifies that an authentication that already holds the factor is returned as it is.
     */
    @Test
    void grant_whenFactorIsPresent_returnsTheSameAuthentication() {
        final var original = UsernamePasswordAuthenticationToken.authenticated("alice", "secret",
                AuthorityUtils.createAuthorityList(AUTHORITY));

        assertSame(original, grantor.grant(original, AUTHORITY));
    }
}
