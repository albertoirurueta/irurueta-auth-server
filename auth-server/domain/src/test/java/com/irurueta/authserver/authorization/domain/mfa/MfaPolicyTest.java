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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Set;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link MfaPolicy}.
 */
class MfaPolicyTest {

    /** Password factor used by the tests. */
    private static final AuthenticationFactor PASSWORD =
            new AuthenticationFactor("password", "pwd", "FACTOR_PASSWORD", FactorStrength.PRIMARY);

    /** Passkey factor used by the tests. */
    private static final AuthenticationFactor PASSKEY =
            new AuthenticationFactor("passkey", "hwk", "FACTOR_WEBAUTHN", FactorStrength.PRIMARY_STRONG);

    /** TOTP factor used by the tests. */
    private static final AuthenticationFactor TOTP =
            new AuthenticationFactor("totp", "otp", "FACTOR_TOTP", FactorStrength.SECOND);

    /** Subject under test. */
    private final MfaPolicy policy = new MfaPolicy();

    /**
     * Verifies that a strong primary factor is enough alone.
     */
    @Test
    void isSatisfied_whenStrongFactorAlone_returnsTrue() {
        assertTrue(policy.isSatisfied(Set.of(PASSKEY)));
    }

    /**
     * Verifies that a password alone is not enough.
     */
    @Test
    void isSatisfied_whenPasswordOnly_returnsFalse() {
        assertFalse(policy.isSatisfied(Set.of(PASSWORD)));
    }

    /**
     * Verifies that a password plus a second factor is enough.
     */
    @Test
    void isSatisfied_whenPasswordAndSecondFactor_returnsTrue() {
        assertTrue(policy.isSatisfied(Set.of(PASSWORD, TOTP)));
    }

    /**
     * Verifies that a second factor without a primary one is not enough.
     */
    @Test
    void isSatisfied_whenSecondFactorOnly_returnsFalse() {
        assertFalse(policy.isSatisfied(Set.of(TOTP)));
    }

    /**
     * Verifies that no factor is not enough.
     */
    @Test
    void isSatisfied_whenNoFactors_returnsFalse() {
        assertFalse(policy.isSatisfied(Set.of()));
    }

    /**
     * Verifies that the client alone makes the second factor required.
     */
    @Test
    void isRequired_whenOnlyClientRequires_returnsTrue() {
        assertTrue(policy.isRequired(true, false));
    }

    /**
     * Verifies that the user alone makes the second factor required.
     */
    @Test
    void isRequired_whenOnlyUserRequires_returnsTrue() {
        assertTrue(policy.isRequired(false, true));
    }

    /**
     * Verifies that nobody requiring it leaves it optional.
     */
    @Test
    void isRequired_whenNobodyRequires_returnsFalse() {
        assertFalse(policy.isRequired(false, false));
    }
}
