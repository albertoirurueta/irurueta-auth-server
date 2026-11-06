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
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.totp.RecoveryCode;
import com.irurueta.authserver.authorization.domain.totp.RecoveryCodeRepository;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link CountRecoveryCodesUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class CountRecoveryCodesUseCaseTest {

    /** Port that stores the recovery codes. */
    @Mock
    private RecoveryCodeRepository recoveryCodeRepository;

    /** Use case under test. */
    @InjectMocks
    private CountRecoveryCodesUseCase useCase;

    /**
     * Verifies that the unused codes are counted.
     */
    @Test
    void execute_whenCalled_countsTheUnusedCodes() {
        final var userId = UUID.randomUUID();
        when(recoveryCodeRepository.findUnused(userId)).thenReturn(List.of(
                new RecoveryCode(UUID.randomUUID(), userId, "a", null),
                new RecoveryCode(UUID.randomUUID(), userId, "b", null)));

        assertEquals(2, useCase.execute(userId));
    }
}
