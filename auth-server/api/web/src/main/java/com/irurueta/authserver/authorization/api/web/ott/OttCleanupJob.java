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
package com.irurueta.authserver.authorization.api.web.ott;

import com.irurueta.authserver.authorization.application.ott.CleanupOttUseCase;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Scheduled entry point that deletes what one-time tokens leave behind once it expired: the numeric codes, the pending
 * phone verifications, the SMS cost ledger entries past their retention and Spring's expired link tokens. The schedule
 * comes from {@code authserver.ott.cleanup.cron} (default every hour, at quarter past). Scheduling itself is enabled
 * once for every feature by {@code SchedulingConfiguration}.
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class OttCleanupJob {

    /** Deletes the expired one-time token data. */
    private final CleanupOttUseCase cleanupOttUseCase;

    /**
     * Deletes the expired one-time token data.
     */
    @Scheduled(cron = "${authserver.ott.cleanup.cron:0 15 * * * *}")
    public void run() {
        log.debug("Deleted expired one-time token data: {}", cleanupOttUseCase.execute());
    }
}
