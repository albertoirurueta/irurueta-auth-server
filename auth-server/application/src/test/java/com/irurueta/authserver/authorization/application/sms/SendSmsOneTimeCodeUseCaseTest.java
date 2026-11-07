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
package com.irurueta.authserver.authorization.application.sms;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.sms.PhoneCountryResolver;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.SmsCostLedgerRepository;
import com.irurueta.authserver.authorization.domain.sms.SmsCostPolicy;
import com.irurueta.authserver.authorization.domain.sms.SmsSpendCap;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.context.ApplicationEventPublisher;

/**
 * Unit tests of {@link SendSmsOneTimeCodeUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class SendSmsOneTimeCodeUseCaseTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Spending window of the policy. */
    private static final Duration WINDOW = Duration.ofHours(1);

    /** Cost of one message. */
    private static final long COST = 100L;

    /** Cap of a window. */
    private static final long WINDOW_CAP = 1_000L;

    /** Cap of a day. */
    private static final long DAY_CAP = 5_000L;

    /** Destination used by the tests. */
    private static final PhoneNumber TO = new PhoneNumber("+34600000000");

    /** Text sent. */
    private static final String TEXT = "Your code";

    /** Port that finds the country. */
    @Mock
    private PhoneCountryResolver phoneCountryResolver;

    /** Real policy: Spain is served, one message costs {@link #COST}. */
    @Spy
    private SmsCostPolicy smsCostPolicy = new SmsCostPolicy(Set.of("ES"), Map.of(), COST, WINDOW, WINDOW_CAP, DAY_CAP);

    /** Port that records the spend. */
    @Mock
    private SmsCostLedgerRepository smsCostLedgerRepository;

    /** Publishes the request to send the message. */
    @Mock
    private ApplicationEventPublisher eventPublisher;

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    @InjectMocks
    private SendSmsOneTimeCodeUseCase useCase;

    /**
     * Verifies that a message within both caps is recorded once, atomically, with its cost and the caps of the policy,
     * and then requested through an event instead of being sent inside the transaction.
     */
    @Test
    void execute_whenWithinCaps_recordsCostAndRequestsTheMessage() {
        stubLedger(true);

        useCase.execute(TO, TEXT);

        verify(smsCostLedgerRepository).tryRecord(NOW, "ES", COST, new SmsSpendCap(WINDOW, WINDOW_CAP),
                new SmsSpendCap(SmsCostPolicy.DAY, DAY_CAP));
        verify(eventPublisher).publishEvent(new SmsRequested(TO, TEXT));
    }

    /**
     * Verifies that an unknown country is refused before anything is recorded or requested.
     */
    @Test
    void execute_whenCountryIsUnknown_throwsSmsCountryNotAllowedException() {
        when(phoneCountryResolver.countryOf(TO)).thenReturn(Optional.empty());

        assertThrows(SmsCountryNotAllowedException.class, () -> useCase.execute(TO, TEXT));

        verifyNoInteractions(smsCostLedgerRepository, eventPublisher);
    }

    /**
     * Verifies that a country that is not served is refused.
     */
    @Test
    void execute_whenCountryIsNotAllowed_throwsSmsCountryNotAllowedException() {
        when(phoneCountryResolver.countryOf(TO)).thenReturn(Optional.of("FR"));

        assertThrows(SmsCountryNotAllowedException.class, () -> useCase.execute(TO, TEXT));

        verifyNoInteractions(smsCostLedgerRepository, eventPublisher);
    }

    /**
     * Verifies that a message the ledger refuses (a cap would be exceeded) is refused and never requested.
     */
    @Test
    void execute_whenACapWouldBeExceeded_throwsSmsBudgetExceededException() {
        stubLedger(false);

        final var error = assertThrows(SmsBudgetExceededException.class, () -> useCase.execute(TO, TEXT));

        assertFalse(error.getMessage().contains(TO.e164()));
        verifyNoInteractions(eventPublisher);
    }

    /**
     * Stubs the country of the destination as Spain, the clock and the answer of the ledger.
     *
     * @param withinCaps whether the ledger records the message.
     */
    private void stubLedger(final boolean withinCaps) {
        when(phoneCountryResolver.countryOf(TO)).thenReturn(Optional.of("ES"));
        when(clock.instant()).thenReturn(NOW);
        when(smsCostLedgerRepository.tryRecord(NOW, "ES", COST, new SmsSpendCap(WINDOW, WINDOW_CAP),
                new SmsSpendCap(SmsCostPolicy.DAY, DAY_CAP))).thenReturn(withinCaps);
    }
}
