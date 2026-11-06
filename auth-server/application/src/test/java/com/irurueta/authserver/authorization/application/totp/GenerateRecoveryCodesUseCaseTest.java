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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.mfa.HasConfirmedSecondFactorUseCase;
import com.irurueta.authserver.authorization.domain.password.PasswordHasher;
import com.irurueta.authserver.authorization.domain.totp.RecoveryCode;
import com.irurueta.authserver.authorization.domain.totp.RecoveryCodeRepository;
import com.irurueta.authserver.authorization.domain.totp.TotpNotEnrolledException;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link GenerateRecoveryCodesUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class GenerateRecoveryCodesUseCaseTest {

    /** Port that stores the recovery codes. */
    @Mock
    private RecoveryCodeRepository recoveryCodeRepository;

    /** Port that hashes the codes. */
    @Mock
    private PasswordHasher passwordHasher;

    /** Creator of the codes. */
    @Mock
    private RecoveryCodes recoveryCodes;

    /** Tells whether the user has confirmed a second factor. */
    @Mock
    private HasConfirmedSecondFactorUseCase hasConfirmedSecondFactorUseCase;

    /** Use case under test. */
    @InjectMocks
    private GenerateRecoveryCodesUseCase useCase;

    /**
     * Verifies that ten codes are returned in clear text and replace the stored ones as hashes.
     */
    @Test
    void execute_whenCalled_storesTenHashedCodesAndReturnsTheClearOnes() {
        final var userId = UUID.randomUUID();
        when(hasConfirmedSecondFactorUseCase.execute(userId)).thenReturn(true);
        when(recoveryCodes.newCode()).thenReturn("ABCDEFGHJK");
        when(passwordHasher.encode(any())).thenReturn("hashed");
        final var captor = ArgumentCaptor.<List<RecoveryCode>>captor();

        final var codes = useCase.execute(userId);

        assertEquals(GenerateRecoveryCodesUseCase.CODE_COUNT, codes.size());
        assertEquals("ABCDEFGHJK", codes.getFirst());
        verify(recoveryCodeRepository).replaceAll(org.mockito.ArgumentMatchers.eq(userId), captor.capture());
        final var stored = captor.getValue();
        assertEquals(GenerateRecoveryCodesUseCase.CODE_COUNT, stored.size());
        assertEquals("hashed", stored.getFirst().hashedCode());
        assertEquals(userId, stored.getFirst().userId());
        assertNull(stored.getFirst().usedAt());
    }

    /**
     * Verifies that a user without a confirmed second factor gets no recovery codes and nothing is stored.
     */
    @Test
    void execute_whenNoSecondFactorIsConfirmed_throwsTotpNotEnrolledException() {
        final var userId = UUID.randomUUID();
        when(hasConfirmedSecondFactorUseCase.execute(userId)).thenReturn(false);

        assertThrows(TotpNotEnrolledException.class, () -> useCase.execute(userId));

        verifyNoInteractions(recoveryCodeRepository, passwordHasher, recoveryCodes);
    }
}
