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

package com.irurueta.authserver.authorization.api.web.tokens;

import com.irurueta.authserver.authorization.application.tokens.CleanExpiredAuthorizationsUseCase;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

// tag::tokens-cleanup-job[]
/**
 * Periodically deletes the expired and the abandoned authorizations. The schedule is the cron expression
 * {@code authserver.tokens.cleanup.cron} (default: every hour). Scheduling is enabled by the feature-neutral
 * {@link com.irurueta.authserver.authorization.api.web.SchedulingConfiguration}.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ExpiredAuthorizationCleanupJob {

    /** Deletes the expired authorizations. */
    private final CleanExpiredAuthorizationsUseCase cleanExpiredAuthorizationsUseCase;

    /**
     * Deletes the expired and the abandoned authorizations.
     */
    @Scheduled(cron = "${authserver.tokens.cleanup.cron:0 0 * * * *}")
    public void run() {
        final var deleted = cleanExpiredAuthorizationsUseCase.execute();
        log.debug("Deleted {} expired or abandoned authorizations", deleted);
    }
}
// end::tokens-cleanup-job[]
