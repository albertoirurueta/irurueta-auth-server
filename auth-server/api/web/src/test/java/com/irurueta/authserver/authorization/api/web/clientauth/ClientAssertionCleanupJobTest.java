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
package com.irurueta.authserver.authorization.api.web.clientauth;

import static org.mockito.Mockito.verify;

import com.irurueta.authserver.authorization.application.clientauth.PurgeClientAssertionsUseCase;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/** Unit tests of {@link ClientAssertionCleanupJob}. */
@ExtendWith(MockitoExtension.class)
class ClientAssertionCleanupJobTest {

    /** Deletes the expired identifiers. */
    @Mock
    private PurgeClientAssertionsUseCase purgeClientAssertions;

    /** Job under test. */
    @InjectMocks
    private ClientAssertionCleanupJob job;

    /** The run calls the use case. */
    @Test
    void run_whenTriggered_callsTheUseCase() {
        job.run();

        verify(purgeClientAssertions).execute();
    }
}
