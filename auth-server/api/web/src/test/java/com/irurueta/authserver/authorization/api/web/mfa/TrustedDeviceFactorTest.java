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

import com.irurueta.authserver.authorization.domain.mfa.AuthenticationFactor;
import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link TrustedDeviceFactor}.
 */
class TrustedDeviceFactorTest {

    /**
     * Verifies that the trusted device is a remembered factor with its own authority.
     */
    @Test
    void trustedDeviceAuthenticationFactor_whenBuilt_isARememberedFactor() {
        assertEquals(new AuthenticationFactor(TrustedDeviceFactor.ID, TrustedDeviceFactor.AMR_VALUE,
                        TrustedDeviceFactor.AUTHORITY, FactorStrength.REMEMBERED),
                new TrustedDeviceFactor().trustedDeviceAuthenticationFactor());
    }
}
