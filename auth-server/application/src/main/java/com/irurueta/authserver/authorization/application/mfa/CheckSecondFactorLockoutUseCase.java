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
import java.time.Clock;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that tells whether the second factor of a user is locked after too many failed attempts.
 */
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class CheckSecondFactorLockoutUseCase {

    /** Port that stores the failed-attempt counters. */
    private final SecondFactorAttemptRepository secondFactorAttemptRepository;

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Checks the lockout of a user.
     *
     * @param userId identifier of the user.
     * @return {@code true} if the second factor is locked right now.
     */
    public boolean execute(final UUID userId) {
        return secondFactorAttemptRepository.find(userId).isLocked(clock.instant());
    }
}
