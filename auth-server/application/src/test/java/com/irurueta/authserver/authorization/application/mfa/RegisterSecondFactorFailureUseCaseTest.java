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

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.mfa.SecondFactorAttemptRepository;
import com.irurueta.authserver.authorization.domain.mfa.SecondFactorLockout;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link RegisterSecondFactorFailureUseCase}. The configured values are constructor parameters of the
 * use case, so it is built by hand instead of with {@code @InjectMocks}.
 */
@ExtendWith(MockitoExtension.class)
class RegisterSecondFactorFailureUseCaseTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Failures that lock. */
    private static final int MAX_ATTEMPTS = 3;

    /** Lockout duration. */
    private static final Duration LOCKOUT = Duration.ofMinutes(15);

    /** Port that stores the failed-attempt counters. */
    @Mock
    private SecondFactorAttemptRepository secondFactorAttemptRepository;

    /** Use case that records the audit events. */
    @Mock
    private RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    private RegisterSecondFactorFailureUseCase useCase;

    /**
     * Creates the use case.
     */
    @BeforeEach
    void setUp() {
        useCase = new RegisterSecondFactorFailureUseCase(
                secondFactorAttemptRepository, recordSecurityEventUseCase, clock, MAX_ATTEMPTS, LOCKOUT);
    }

    /**
     * Verifies that a failure below the limit is counted and audited, with no lockout event.
     */
    @Test
    void execute_whenBelowTheLimit_recordsOnlyTheFailure() {
        final var userId = UUID.randomUUID();
        final var state = new SecondFactorLockout(1, null);
        when(clock.instant()).thenReturn(NOW);
        when(secondFactorAttemptRepository.recordFailure(userId, MAX_ATTEMPTS, LOCKOUT, NOW)).thenReturn(state);

        assertSame(state, useCase.execute(userId, "alice"));

        verify(recordSecurityEventUseCase).execute(SecurityEventType.SECOND_FACTOR_FAILURE, userId, "alice", null);
        verify(recordSecurityEventUseCase, never()).execute(
                ArgumentMatchers.eq(SecurityEventType.SECOND_FACTOR_LOCKED), ArgumentMatchers.any(),
                ArgumentMatchers.any(), ArgumentMatchers.any());
    }

    /**
     * Verifies that reaching the limit also audits the lockout.
     */
    @Test
    void execute_whenTheLimitIsReached_recordsTheLockout() {
        final var userId = UUID.randomUUID();
        final var until = NOW.plus(LOCKOUT);
        when(clock.instant()).thenReturn(NOW);
        when(secondFactorAttemptRepository.recordFailure(userId, MAX_ATTEMPTS, LOCKOUT, NOW))
                .thenReturn(new SecondFactorLockout(MAX_ATTEMPTS, until));

        useCase.execute(userId, "alice");

        verify(recordSecurityEventUseCase).execute(SecurityEventType.SECOND_FACTOR_FAILURE, userId, "alice", null);
        verify(recordSecurityEventUseCase).execute(
                SecurityEventType.SECOND_FACTOR_LOCKED, userId, "alice", "locked until " + until);
    }
}
