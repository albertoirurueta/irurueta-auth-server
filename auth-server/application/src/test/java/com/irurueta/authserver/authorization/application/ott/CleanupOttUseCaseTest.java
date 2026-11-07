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

package com.irurueta.authserver.authorization.application.ott;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.sms.SmsProperties;
import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeRepository;
import com.irurueta.authserver.authorization.domain.sms.PhoneVerificationRepository;
import com.irurueta.authserver.authorization.domain.sms.SmsCostLedgerRepository;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link CleanupOttUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class CleanupOttUseCaseTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-10T00:00:00Z");

    /** Retention of the ledger. */
    private static final Duration RETENTION = Duration.ofDays(3);

    /** Expired codes. */
    private static final int CODES = 4;

    /** Expired verifications. */
    private static final int VERIFICATIONS = 3;

    /** Old ledger rows. */
    private static final int LEDGER = 2;

    /** Expired link tokens. */
    private static final int TOKENS = 5;

    /** Port that stores the codes. */
    @Mock
    private OneTimeCodeRepository oneTimeCodeRepository;

    /** Port that stores the pending verifications. */
    @Mock
    private PhoneVerificationRepository phoneVerificationRepository;

    /** Port that stores the spend. */
    @Mock
    private SmsCostLedgerRepository smsCostLedgerRepository;

    /** Port that purges the link tokens. */
    @Mock
    private ExpiredLinkTokenPurger expiredLinkTokenPurger;

    /** Settings with a three-day ledger retention. */
    @Spy
    private SmsProperties smsProperties = new SmsProperties(null, null, null, 0L, null, 0L, 0L, 0, null, 0, RETENTION);

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    @InjectMocks
    private CleanupOttUseCase useCase;

    /**
     * Verifies that every store is cleaned with the right cutoff and the counts are reported.
     */
    @Test
    void execute_whenCalled_cleansEveryStoreAndReportsCounts() {
        when(clock.instant()).thenReturn(NOW);
        when(oneTimeCodeRepository.deleteExpired(NOW)).thenReturn(CODES);
        when(phoneVerificationRepository.deleteExpired(NOW)).thenReturn(VERIFICATIONS);
        when(smsCostLedgerRepository.deleteOlderThan(NOW.minus(RETENTION))).thenReturn(LEDGER);
        when(expiredLinkTokenPurger.deleteExpired(NOW)).thenReturn(TOKENS);

        final var result = useCase.execute();

        assertEquals(new OttCleanupResult(CODES, VERIFICATIONS, LEDGER, TOKENS), result);
        verify(smsCostLedgerRepository).deleteOlderThan(NOW.minus(RETENTION));
    }
}
