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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.SmsCostLedgerRepository;
import com.irurueta.authserver.authorization.domain.sms.SmsCostPolicy;
import com.irurueta.authserver.authorization.domain.sms.SmsDeliveryException;
import com.irurueta.authserver.authorization.domain.sms.SmsSender;
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

    /** Port that sends the message. */
    @Mock
    private SmsSender smsSender;

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    @InjectMocks
    private SendSmsOneTimeCodeUseCase useCase;

    /**
     * Verifies that a message within both caps is recorded once with its cost and sent.
     */
    @Test
    void execute_whenWithinCaps_recordsCostAndSends() {
        stubCountry();
        when(clock.instant()).thenReturn(NOW);
        when(smsCostLedgerRepository.recordAndGetSpend(NOW, "ES", 0L, WINDOW)).thenReturn(WINDOW_CAP - COST);
        when(smsCostLedgerRepository.recordAndGetSpend(NOW, "ES", 0L, Duration.ofDays(1))).thenReturn(DAY_CAP - COST);

        useCase.execute(TO, TEXT);

        verify(smsCostLedgerRepository).recordAndGetSpend(NOW, "ES", COST, WINDOW);
        verify(smsSender).send(TO, TEXT);
    }

    /**
     * Verifies that an unknown country is refused before anything is recorded or sent.
     */
    @Test
    void execute_whenCountryIsUnknown_throwsSmsCountryNotAllowedException() {
        when(phoneCountryResolver.countryOf(TO)).thenReturn(Optional.empty());

        assertThrows(SmsCountryNotAllowedException.class, () -> useCase.execute(TO, TEXT));

        verifyNoInteractions(smsCostLedgerRepository, smsSender);
    }

    /**
     * Verifies that a country that is not served is refused.
     */
    @Test
    void execute_whenCountryIsNotAllowed_throwsSmsCountryNotAllowedException() {
        when(phoneCountryResolver.countryOf(TO)).thenReturn(Optional.of("FR"));

        assertThrows(SmsCountryNotAllowedException.class, () -> useCase.execute(TO, TEXT));

        verifyNoInteractions(smsCostLedgerRepository, smsSender);
    }

    /**
     * Verifies that exceeding the window cap refuses the message and records no spend.
     */
    @Test
    void execute_whenWindowCapWouldBeExceeded_throwsSmsBudgetExceededException() {
        stubCountry();
        when(clock.instant()).thenReturn(NOW);
        when(smsCostLedgerRepository.recordAndGetSpend(NOW, "ES", 0L, WINDOW)).thenReturn(WINDOW_CAP - COST + 1);
        when(smsCostLedgerRepository.recordAndGetSpend(NOW, "ES", 0L, Duration.ofDays(1))).thenReturn(0L);

        assertThrows(SmsBudgetExceededException.class, () -> useCase.execute(TO, TEXT));

        verify(smsCostLedgerRepository, never()).recordAndGetSpend(NOW, "ES", COST, WINDOW);
        verifyNoInteractions(smsSender);
    }

    /**
     * Verifies that exceeding the daily cap refuses the message and records no spend.
     */
    @Test
    void execute_whenDailyCapWouldBeExceeded_throwsSmsBudgetExceededException() {
        stubCountry();
        when(clock.instant()).thenReturn(NOW);
        when(smsCostLedgerRepository.recordAndGetSpend(NOW, "ES", 0L, WINDOW)).thenReturn(0L);
        when(smsCostLedgerRepository.recordAndGetSpend(NOW, "ES", 0L, Duration.ofDays(1)))
                .thenReturn(DAY_CAP - COST + 1);

        final var error = assertThrows(SmsBudgetExceededException.class, () -> useCase.execute(TO, TEXT));

        assertFalse(error.getMessage().contains(TO.e164()));
        verify(smsCostLedgerRepository, never()).recordAndGetSpend(NOW, "ES", COST, WINDOW);
        verifyNoInteractions(smsSender);
    }

    /**
     * Verifies that a provider failure propagates as is.
     */
    @Test
    void execute_whenProviderFails_propagatesSmsDeliveryException() {
        stubCountry();
        when(clock.instant()).thenReturn(NOW);
        when(smsCostLedgerRepository.recordAndGetSpend(eq(NOW), eq("ES"), eq(0L), any()))
                .thenReturn(0L);
        final var failure = new SmsDeliveryException("provider down", new IllegalStateException());
        doThrow(failure).when(smsSender).send(TO, TEXT);

        final var thrown = assertThrows(SmsDeliveryException.class, () -> useCase.execute(TO, TEXT));

        assertSame(failure, thrown);
    }

    /**
     * Stubs the country of the destination as Spain.
     */
    private void stubCountry() {
        when(phoneCountryResolver.countryOf(TO)).thenReturn(Optional.of("ES"));
    }
}
