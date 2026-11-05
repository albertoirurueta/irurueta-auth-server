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

package com.irurueta.authserver.authorization.application.account;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.account.AccountTokenRepository;
import java.time.Clock;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link CleanExpiredAccountTokensUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class CleanExpiredAccountTokensUseCaseTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Number of tokens the mocked port reports as deleted. */
    private static final int DELETED = 4;

    /** Port that stores the account tokens. */
    @Mock
    private AccountTokenRepository accountTokenRepository;

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    @InjectMocks
    private CleanExpiredAccountTokensUseCase useCase;

    /**
     * Verifies that the tokens expired at the current instant are deleted and their number returned.
     */
    @Test
    void execute_whenCalled_deletesTokensExpiredNow() {
        when(clock.instant()).thenReturn(NOW);
        when(accountTokenRepository.deleteExpired(NOW)).thenReturn(DELETED);

        assertEquals(DELETED, useCase.execute());
    }
}
