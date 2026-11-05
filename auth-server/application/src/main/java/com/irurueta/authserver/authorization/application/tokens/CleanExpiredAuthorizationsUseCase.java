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
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

/**
 * Use case that deletes the authorizations whose tokens have all expired, and the abandoned ones: authorization or
 * consent requests that never got a token and are older than a threshold.
 */
@Service
@RequiredArgsConstructor
public class CleanExpiredAuthorizationsUseCase {

    /** Port that removes stored authorizations. */
    private final UserAuthorizationRepository userAuthorizationRepository;

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Age after which an authorization that never got a token is deleted
     * ({@code authserver.tokens.cleanup.abandoned-after}, default 1 day).
     */
    @Value("${authserver.tokens.cleanup.abandoned-after:P1D}")
    private final Duration abandonedAfter;

    /**
     * Deletes the expired and the abandoned authorizations.
     *
     * @return the number of deleted authorizations.
     */
    public int execute() {
        final var now = clock.instant();
        return userAuthorizationRepository.deleteExpired(now)
                + userAuthorizationRepository.deleteAbandoned(now.minus(abandonedAfter));
    }
}
