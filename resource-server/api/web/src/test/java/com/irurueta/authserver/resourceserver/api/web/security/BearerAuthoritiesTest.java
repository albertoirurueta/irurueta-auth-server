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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * Unit tests for {@link BearerAuthorities}.
 */
class BearerAuthoritiesTest {

    /** Adds the prefix only when it is missing. */
    @Test
    void roleAuthorities_whenRolesAreGiven_addsThePrefixOnlyWhenMissing() {
        final var authorities = BearerAuthorities.roleAuthorities(List.of("ADMIN", "ROLE_USER"));

        assertEquals(List.of("ROLE_ADMIN", "ROLE_USER"),
                authorities.stream().map(GrantedAuthority::getAuthority).toList());
    }

    /** No roles claim means no authorities. */
    @Test
    void roleAuthorities_whenRolesAreNull_returnsNoAuthorities() {
        assertTrue(BearerAuthorities.roleAuthorities(null).isEmpty());
    }

    /** The administrator role is detected. */
    @Test
    void isAdministrator_whenCallerHoldsTheAdminRole_isTrue() {
        assertTrue(BearerAuthorities.isAdministrator(new TestingAuthenticationToken("a", null, "ROLE_ADMIN")));
    }

    /** Other authorities are not enough. */
    @Test
    void isAdministrator_whenCallerHoldsOtherAuthorities_isFalse() {
        assertFalse(BearerAuthorities.isAdministrator(new TestingAuthenticationToken("a", null, "ROLE_USER")));
    }
}
