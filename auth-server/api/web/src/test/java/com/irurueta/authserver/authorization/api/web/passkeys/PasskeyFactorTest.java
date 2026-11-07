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

package com.irurueta.authserver.authorization.api.web.passkeys;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link PasskeyFactor}.
 */
class PasskeyFactorTest {

    /**
     * Verifies that the factor is a strong primary one that Spring Security grants as {@code FACTOR_WEBAUTHN} and
     * that the tokens report as {@code hwk}.
     */
    @Test
    void passkeyAuthenticationFactor_whenCalled_declaresAStrongPrimaryFactor() {
        final var factor = new PasskeyFactor().passkeyAuthenticationFactor();

        assertEquals("passkey", factor.id());
        assertEquals("hwk", factor.amrValue());
        assertEquals("FACTOR_WEBAUTHN", factor.authority());
        assertEquals(FactorStrength.PRIMARY_STRONG, factor.strength());
    }
}
