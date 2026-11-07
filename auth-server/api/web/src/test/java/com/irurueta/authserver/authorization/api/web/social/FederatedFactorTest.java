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

package com.irurueta.authserver.authorization.api.web.social;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link FederatedFactor}.
 */
class FederatedFactorTest {

    /** Declarations under test. */
    private final FederatedFactor declarations = new FederatedFactor();

    /**
     * Verifies that the ordinary federated sign-in is a primary factor reported as {@code fed}.
     */
    @Test
    void federatedAuthenticationFactor_whenCalled_declaresAPrimaryFactor() {
        final var factor = declarations.federatedAuthenticationFactor();

        assertEquals("federated", factor.id());
        assertEquals("fed", factor.amrValue());
        assertEquals("FACTOR_FEDERATED", factor.authority());
        assertEquals(FactorStrength.PRIMARY, factor.strength());
    }

    /**
     * Verifies that the sign-in of a trusted provider that proved several factors is a strong primary factor, reported
     * the same way.
     */
    @Test
    void federatedStrongAuthenticationFactor_whenCalled_declaresAStrongPrimaryFactor() {
        final var factor = declarations.federatedStrongAuthenticationFactor();

        assertEquals("federated-mfa", factor.id());
        assertEquals("fed", factor.amrValue());
        assertEquals("FACTOR_FEDERATED_MFA", factor.authority());
        assertEquals(FactorStrength.PRIMARY_STRONG, factor.strength());
    }
}
