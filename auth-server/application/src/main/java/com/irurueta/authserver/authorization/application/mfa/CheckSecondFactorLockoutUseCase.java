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

// tag::mfa-lockout-check[]
/**
 * Use case that tells whether the second factor of a user is locked after too many failed attempts. It locks the
 * user's attempt row until the end of the caller's transaction, so the verifications of the same user (each a
 * transactional use case that starts with this check) run one at a time: none of them can pass the check while
 * another one is about to count a failure.
 */
@Service
@Transactional
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
        return secondFactorAttemptRepository.lockForUpdate(userId).isLocked(clock.instant());
    }
}
// end::mfa-lockout-check[]
