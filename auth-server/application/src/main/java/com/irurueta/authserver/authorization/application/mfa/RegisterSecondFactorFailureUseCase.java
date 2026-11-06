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

import com.irurueta.authserver.authorization.domain.mfa.SecondFactorAttemptRepository;
import com.irurueta.authserver.authorization.domain.mfa.SecondFactorLockout;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import java.time.Clock;
import java.time.Duration;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that counts a failed second-factor attempt and locks the second factor of the user once
 * {@code authserver.mfa.max-failed-attempts} consecutive failures are reached. Both the failure and the lockout are
 * audited. The counter is stored, never kept in memory.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class RegisterSecondFactorFailureUseCase {

    /** Port that stores the failed-attempt counters. */
    private final SecondFactorAttemptRepository secondFactorAttemptRepository;

    /** Use case that records the audit events. */
    private final RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Source of the current time. */
    private final Clock clock;

    /** Consecutive failures that lock the second factor ({@code authserver.mfa.max-failed-attempts}, default 5). */
    @Value("${authserver.mfa.max-failed-attempts:5}")
    private final int maxFailedAttempts;

    /** How long the second factor stays locked ({@code authserver.mfa.lockout}, default 15 minutes). */
    @Value("${authserver.mfa.lockout:PT15M}")
    private final Duration lockout;

    /**
     * Registers a failed attempt.
     *
     * @param userId   identifier of the user.
     * @param username name of the user, for the audit log.
     * @return the state of the counter after the failure.
     */
    public SecondFactorLockout execute(final UUID userId, final String username) {
        final var now = clock.instant();
        final var state = secondFactorAttemptRepository.recordFailure(userId, maxFailedAttempts, lockout, now);
        recordSecurityEventUseCase.execute(SecurityEventType.SECOND_FACTOR_FAILURE, userId, username, null);
        if (state.isLocked(now)) {
            recordSecurityEventUseCase.execute(SecurityEventType.SECOND_FACTOR_LOCKED, userId, username,
                    "locked until " + state.lockedUntil());
        }
        return state;
    }
}
