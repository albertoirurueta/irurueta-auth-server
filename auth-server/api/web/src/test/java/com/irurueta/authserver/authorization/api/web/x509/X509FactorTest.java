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
package com.irurueta.authserver.authorization.api.web.x509;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.irurueta.authserver.authorization.domain.mfa.FactorStrength;
import java.util.List;
import org.junit.jupiter.api.Test;

/**
 * Unit tests of {@link X509Factor}.
 */
class X509FactorTest {

    /** Factor declarations under test. */
    private final X509Factor factor = new X509Factor();

    /**
     * Verifies that the factor is a strong primary one that reports {@code sc} by default.
     */
    @Test
    void x509AuthenticationFactor_whenSmartCard_isAStrongPrimaryFactorReportingSc() {
        final var declared = factor.x509AuthenticationFactor(properties("sc"));

        assertEquals("x509", declared.id());
        assertEquals("sc", declared.amrValue());
        assertEquals("FACTOR_X509", declared.authority());
        assertEquals(FactorStrength.PRIMARY_STRONG, declared.strength());
    }

    /**
     * Verifies that the reported value follows the configuration.
     */
    @Test
    void x509AuthenticationFactor_whenHardwareKey_reportsHwk() {
        assertEquals("hwk", factor.x509AuthenticationFactor(properties("hwk")).amrValue());
    }

    /**
     * Builds the settings.
     *
     * @param amr the {@code amr} value.
     * @return the settings.
     */
    private static X509Properties properties(final String amr) {
        return new X509Properties(true, "", List.of(), 0, amr, "", "", "PKCS12");
    }
}
