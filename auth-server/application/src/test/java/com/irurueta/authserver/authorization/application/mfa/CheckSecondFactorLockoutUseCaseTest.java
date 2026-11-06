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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.mfa.SecondFactorAttemptRepository;
import com.irurueta.authserver.authorization.domain.mfa.SecondFactorLockout;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link CheckSecondFactorLockoutUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class CheckSecondFactorLockoutUseCaseTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Failures of the locked user. */
    private static final int FAILURES = 5;

    /** Port that stores the failed-attempt counters. */
    @Mock
    private SecondFactorAttemptRepository secondFactorAttemptRepository;

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    @InjectMocks
    private CheckSecondFactorLockoutUseCase useCase;

    /**
     * Verifies that a user locked until a later instant is reported as locked.
     */
    @Test
    void execute_whenLockedUntilLater_returnsTrue() {
        final var userId = UUID.randomUUID();
        when(clock.instant()).thenReturn(NOW);
        when(secondFactorAttemptRepository.find(userId))
                .thenReturn(new SecondFactorLockout(FAILURES, NOW.plusSeconds(1)));

        assertTrue(useCase.execute(userId));
    }

    /**
     * Verifies that a user with no lockout is not reported as locked.
     */
    @Test
    void execute_whenNotLocked_returnsFalse() {
        final var userId = UUID.randomUUID();
        when(clock.instant()).thenReturn(NOW);
        when(secondFactorAttemptRepository.find(userId)).thenReturn(SecondFactorLockout.none());

        assertFalse(useCase.execute(userId));
    }
}
