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
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that clears the failed second-factor attempts of a user, after a successful verification.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class ResetSecondFactorFailuresUseCase {

    /** Port that stores the failed-attempt counters. */
    private final SecondFactorAttemptRepository secondFactorAttemptRepository;

    /**
     * Clears the counter and any lockout of a user.
     *
     * @param userId identifier of the user.
     */
    public void execute(final UUID userId) {
        secondFactorAttemptRepository.reset(userId);
    }
}
