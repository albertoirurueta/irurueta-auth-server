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

package com.irurueta.authserver.authorization.application.totp;

import static org.mockito.Mockito.verify;

import com.irurueta.authserver.authorization.domain.totp.RecoveryCodeRepository;
import com.irurueta.authserver.authorization.domain.totp.TotpCredentialRepository;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link DisableTotpUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class DisableTotpUseCaseTest {

    /** Port that stores the TOTP credentials. */
    @Mock
    private TotpCredentialRepository totpCredentialRepository;

    /** Port that stores the recovery codes. */
    @Mock
    private RecoveryCodeRepository recoveryCodeRepository;

    /** Use case under test. */
    @InjectMocks
    private DisableTotpUseCase useCase;

    /**
     * Verifies that both the credential and the recovery codes are deleted.
     */
    @Test
    void execute_whenCalled_deletesTheCredentialAndTheRecoveryCodes() {
        final var userId = UUID.randomUUID();

        useCase.execute(userId);

        verify(totpCredentialRepository).deleteByUser(userId);
        verify(recoveryCodeRepository).deleteByUser(userId);
    }
}
