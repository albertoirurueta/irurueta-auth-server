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

import static org.junit.jupiter.api.Assertions.assertInstanceOf;

import com.irurueta.authserver.authorization.api.web.mfa.FactorGrantor;
import com.irurueta.authserver.authorization.api.web.mfa.SecondFactorUserResolver;
import com.irurueta.authserver.authorization.api.web.mfa.TrustedDeviceCookieWriter;
import com.irurueta.authserver.authorization.application.mfa.CreateTrustedDeviceUseCase;
import com.irurueta.authserver.authorization.application.mfa.FindTrustedDeviceUseCase;
import com.irurueta.authserver.authorization.application.totp.VerifyRecoveryCodeUseCase;
import com.irurueta.authserver.authorization.application.totp.VerifyTotpUseCase;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link TotpConfiguration}.
 */
@ExtendWith(MockitoExtension.class)
class TotpConfigurationTest {

    /** Verifies TOTP codes. */
    @Mock
    private VerifyTotpUseCase verifyTotpUseCase;

    /** Verifies recovery codes. */
    @Mock
    private VerifyRecoveryCodeUseCase verifyRecoveryCodeUseCase;

    /** Remembers devices. */
    @Mock
    private CreateTrustedDeviceUseCase createTrustedDeviceUseCase;

    /** Finds devices. */
    @Mock
    private FindTrustedDeviceUseCase findTrustedDeviceUseCase;

    /** Resolves the account of the user. */
    @Mock
    private SecondFactorUserResolver userResolver;

    /** Adds the factor. */
    @Mock
    private FactorGrantor factorGrantor;

    /** Writes the device cookie. */
    @Mock
    private TrustedDeviceCookieWriter cookieWriter;

    /**
     * Verifies that the customizer of the TOTP factor is built.
     */
    @Test
    void totpChainCustomizer_whenBuilt_isATotpChainCustomizer() {
        final var customizer = new TotpConfiguration().totpChainCustomizer(verifyTotpUseCase,
                verifyRecoveryCodeUseCase, createTrustedDeviceUseCase, findTrustedDeviceUseCase, userResolver,
                factorGrantor, cookieWriter);

        assertInstanceOf(TotpChainCustomizer.class, customizer);
    }
}
