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

package com.irurueta.authserver.authorization.application.tokens;

import com.irurueta.authserver.authorization.domain.tokens.UserAuthorizationRepository;
import java.time.Clock;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Use case that deletes the authorizations whose tokens have all expired.
 */
@Service
@RequiredArgsConstructor
public class CleanExpiredAuthorizationsUseCase {

    /** Port that removes stored authorizations. */
    private final UserAuthorizationRepository userAuthorizationRepository;

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Deletes the expired authorizations.
     *
     * @return the number of deleted authorizations.
     */
    public int execute() {
        return userAuthorizationRepository.deleteExpired(clock.instant());
    }
}
