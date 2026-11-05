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

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;

import com.irurueta.authserver.authorization.application.account.CleanExpiredAccountTokensUseCase;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.scheduling.annotation.Scheduled;

/**
 * Unit tests of {@link ExpiredAccountTokenCleanupJob}.
 */
@ExtendWith(MockitoExtension.class)
class ExpiredAccountTokenCleanupJobTest {

    /** Deletes the expired account tokens. */
    @Mock
    private CleanExpiredAccountTokensUseCase useCase;

    /** Subject under test. */
    @InjectMocks
    private ExpiredAccountTokenCleanupJob job;

    /**
     * The job runs the clean-up use case.
     */
    @Test
    void run_whenTriggered_cleansExpiredAccountTokens() {
        job.run();

        verify(useCase).execute();
    }

    /**
     * The schedule comes from the {@code authserver.account.cleanup.cron} property.
     *
     * @throws NoSuchMethodException if the method is missing.
     */
    @Test
    void run_whenInspected_isScheduledFromCronProperty() throws NoSuchMethodException {
        final var scheduled = ExpiredAccountTokenCleanupJob.class.getMethod("run").getAnnotation(Scheduled.class);

        assertTrue(scheduled.cron().contains("authserver.account.cleanup.cron"));
    }
}
