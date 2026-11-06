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

package com.irurueta.authserver.authorization.api.web.totp;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.FactorGrantedAuthority;

/**
 * Unit tests of {@link TotpFactor}.
 */
class TotpFactorTest {

    /**
     * Verifies that TOTP is a second factor with a custom factor authority and the {@code otp} amr value.
     */
    @Test
    void totpAuthenticationFactor_whenCalled_returnsSecondTotpFactor() {
        final var factor = new TotpFactor().totpAuthenticationFactor();

        assertEquals("totp", factor.id());
        assertEquals("otp", factor.amrValue());
        assertEquals("FACTOR_TOTP", factor.authority());
        assertEquals(FactorStrength.SECOND, factor.strength());
    }

    /**
     * Verifies that the authority is a valid Spring Security factor authority.
     */
    @Test
    void authority_whenBuiltAsFactorAuthority_keepsItsName() {
        assertEquals(TotpFactor.AUTHORITY, FactorGrantedAuthority.fromAuthority(TotpFactor.AUTHORITY).getAuthority());
    }
}
