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

package com.irurueta.authserver.authorization.api.web.account;

import com.irurueta.authserver.authorization.application.account.CleanExpiredAccountTokensUseCase;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Scheduled entry point that deletes the expired account tokens (password reset links), next to the clean-up of
 * the expired authorizations. The schedule comes from {@code authserver.account.cleanup.cron} (default every hour,
 * at half past).
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class ExpiredAccountTokenCleanupJob {

    /** Deletes the expired account tokens. */
    private final CleanExpiredAccountTokensUseCase cleanExpiredAccountTokensUseCase;

    /**
     * Deletes the expired account tokens.
     */
    @Scheduled(cron = "${authserver.account.cleanup.cron:0 30 * * * *}")
    public void run() {
        log.debug("Deleted {} expired account tokens", cleanExpiredAccountTokensUseCase.execute());
    }
}
