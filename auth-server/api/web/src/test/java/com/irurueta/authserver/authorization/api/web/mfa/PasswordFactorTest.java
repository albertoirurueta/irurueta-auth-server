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

import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.FactorGrantedAuthority;

/**
 * Unit tests of {@link PasswordFactor}.
 */
class PasswordFactorTest {

    /**
     * Verifies that the password is a primary factor proved by Spring Security's password authority.
     */
    @Test
    void passwordAuthenticationFactor_whenCalled_returnsPrimaryPasswordFactor() {
        final var factor = new PasswordFactor().passwordAuthenticationFactor();

        assertEquals("password", factor.id());
        assertEquals("pwd", factor.amrValue());
        assertEquals(FactorGrantedAuthority.PASSWORD_AUTHORITY, factor.authority());
        assertEquals(FactorStrength.PRIMARY, factor.strength());
    }
}
