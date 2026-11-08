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
package com.irurueta.authserver.authorization.domain.mfa;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link AuthenticationFactor}.
 */
class AuthenticationFactorTest {

    /**
     * Verifies that valid values are kept.
     */
    @Test
    void constructor_whenValuesAreValid_keepsThem() {
        final var factor = new AuthenticationFactor("totp", "otp", "FACTOR_TOTP", FactorStrength.SECOND);

        assertEquals("totp", factor.id());
        assertEquals("otp", factor.amrValue());
        assertEquals("FACTOR_TOTP", factor.authority());
        assertEquals(FactorStrength.SECOND, factor.strength());
        assertFalse(factor.multiFactor());
    }

    /**
     * Verifies that a strong factor may prove a multi-factor authentication alone.
     */
    @Test
    void constructor_whenStrongFactorIsMultiFactorAlone_keepsIt() {
        assertTrue(new AuthenticationFactor("federated-mfa", "fed", "FACTOR_FEDERATED_MFA",
                FactorStrength.PRIMARY_STRONG, true).multiFactor());
    }

    /**
     * Verifies that only a strong primary factor may prove a multi-factor authentication alone.
     */
    @Test
    void constructor_whenWeakerFactorClaimsMultiFactor_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new AuthenticationFactor("password", "pwd", "FACTOR_PASSWORD", FactorStrength.PRIMARY, true));
        assertThrows(IllegalArgumentException.class,
                () -> new AuthenticationFactor("totp", "otp", "FACTOR_TOTP", FactorStrength.SECOND, true));
    }

    /**
     * Verifies that a blank id is rejected.
     */
    @Test
    void constructor_whenIdIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new AuthenticationFactor(" ", "otp", "FACTOR_TOTP", FactorStrength.SECOND));
    }

    /**
     * Verifies that a blank amr value is rejected.
     */
    @Test
    void constructor_whenAmrValueIsBlank_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new AuthenticationFactor("totp", "", "FACTOR_TOTP", FactorStrength.SECOND));
    }

    /**
     * Verifies that a missing authority is rejected.
     */
    @Test
    void constructor_whenAuthorityIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new AuthenticationFactor("totp", "otp", null, FactorStrength.SECOND));
    }

    /**
     * Verifies that a missing strength is rejected.
     */
    @Test
    void constructor_whenStrengthIsNull_throwsIllegalArgumentException() {
        assertThrows(IllegalArgumentException.class,
                () -> new AuthenticationFactor("totp", "otp", "FACTOR_TOTP", null));
    }
}
