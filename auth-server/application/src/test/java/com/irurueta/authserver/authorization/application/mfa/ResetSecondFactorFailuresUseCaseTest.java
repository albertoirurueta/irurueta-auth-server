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

package com.irurueta.authserver.authorization.application.mfa;

import static org.mockito.Mockito.verify;

import com.irurueta.authserver.authorization.domain.mfa.SecondFactorAttemptRepository;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link ResetSecondFactorFailuresUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class ResetSecondFactorFailuresUseCaseTest {

    /** Port that stores the failed-attempt counters. */
    @Mock
    private SecondFactorAttemptRepository secondFactorAttemptRepository;

    /** Use case under test. */
    @InjectMocks
    private ResetSecondFactorFailuresUseCase useCase;

    /**
     * Verifies that the counter of the user is reset.
     */
    @Test
    void execute_whenCalled_resetsTheCounter() {
        final var userId = UUID.randomUUID();

        useCase.execute(userId);

        verify(secondFactorAttemptRepository).reset(userId);
    }
}
