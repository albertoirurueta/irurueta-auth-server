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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.FactorGrantedAuthority;

/**
 * Unit tests of {@link AuthenticationFactorRegistry}.
 */
class AuthenticationFactorRegistryTest {

    /** Password factor. */
    private static final AuthenticationFactor PASSWORD = new AuthenticationFactor("password", "pwd",
            FactorGrantedAuthority.PASSWORD_AUTHORITY, FactorStrength.PRIMARY);

    /** TOTP factor. */
    private static final AuthenticationFactor TOTP = new AuthenticationFactor("totp", "otp", "FACTOR_TOTP",
            FactorStrength.SECOND);

    /**
     * Verifies that two factors with the same authority are rejected.
     */
    @Test
    void constructor_whenAuthorityIsRegisteredTwice_throwsIllegalArgumentException() {
        final var factors = List.of(PASSWORD, PASSWORD);

        assertThrows(IllegalArgumentException.class, () -> new AuthenticationFactorRegistry(factors));
    }

    /**
     * Verifies that all the factors are listed in registration order.
     */
    @Test
    void all_whenFactorsAreRegistered_listsThemInOrder() {
        assertEquals(List.of(PASSWORD, TOTP), new AuthenticationFactorRegistry(List.of(PASSWORD, TOTP)).all());
    }

    /**
     * Verifies the lookup by authority, found and not found.
     */
    @Test
    void findByAuthority_whenAuthorityIsOrIsNotRegistered_returnsFactorOrEmpty() {
        final var registry = new AuthenticationFactorRegistry(List.of(PASSWORD, TOTP));

        assertEquals(TOTP, registry.findByAuthority("FACTOR_TOTP").orElseThrow());
        assertTrue(registry.findByAuthority("FACTOR_OTHER").isEmpty());
    }

    /**
     * Verifies the lookup by strength.
     */
    @Test
    void withStrength_whenFactorsHaveDifferentStrengths_returnsTheMatchingOnes() {
        final var registry = new AuthenticationFactorRegistry(List.of(PASSWORD, TOTP));

        assertEquals(List.of(TOTP), registry.withStrength(FactorStrength.SECOND));
        assertTrue(registry.withStrength(FactorStrength.PRIMARY_STRONG).isEmpty());
    }

    /**
     * Verifies that only the registered factor authorities of an authentication are reported.
     */
    @Test
    void factorsOf_whenAuthenticationHasFactorAndOtherAuthorities_returnsOnlyRegisteredFactors() {
        final var registry = new AuthenticationFactorRegistry(List.of(PASSWORD, TOTP));
        final var authentication = UsernamePasswordAuthenticationToken.authenticated("alice", null,
                AuthorityUtils.createAuthorityList(FactorGrantedAuthority.PASSWORD_AUTHORITY, "ROLE_USER",
                        "FACTOR_UNKNOWN"));

        assertEquals(Set.of(PASSWORD), registry.factorsOf(authentication));
    }
}
