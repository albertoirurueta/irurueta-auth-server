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
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.sms.SendSmsOneTimeCodeUseCase;
import com.irurueta.authserver.authorization.application.sms.SmsBudgetExceededException;
import com.irurueta.authserver.authorization.application.sms.SmsCountryNotAllowedException;
import com.irurueta.authserver.authorization.domain.ott.OneTimeCode;
import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeGenerator;
import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeHasher;
import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeRepository;
import com.irurueta.authserver.authorization.domain.ott.OttChannel;
import com.irurueta.authserver.authorization.domain.ott.OttDelivery;
import com.irurueta.authserver.authorization.domain.ott.OttDeliveryException;
import com.irurueta.authserver.authorization.domain.ott.OttPolicy;
import com.irurueta.authserver.authorization.domain.ott.OttPurpose;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.SmsDeliveryException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link RequestOneTimeCodeUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class RequestOneTimeCodeUseCaseTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Username used by the tests. */
    private static final String USERNAME = "alice";

    /** Binding used by the tests. */
    private static final String BINDING = "session-1";

    /** Clear code produced by the mocked generator. */
    private static final String CODE = "123456";

    /** Hash produced by the mocked hasher. */
    private static final String HASH = "hash-of-code";

    /** E-mail destination. */
    private static final String EMAIL = "alice@example.test";

    /** Phone destination. */
    private static final String PHONE = "+34600000000";

    /** Length of the codes. */
    private static final int LENGTH = 6;

    /** Validity of the codes. */
    private static final Duration TTL = Duration.ofMinutes(10);

    /** Use case that finds where to deliver. */
    @Mock
    private ResolveOttDestinationUseCase resolveOttDestinationUseCase;

    /** Generator of codes. */
    @Mock
    private OneTimeCodeGenerator oneTimeCodeGenerator;

    /** Hasher of codes. */
    @Mock
    private OneTimeCodeHasher oneTimeCodeHasher;

    /** Port that stores the codes. */
    @Mock
    private OneTimeCodeRepository oneTimeCodeRepository;

    /** Port that delivers by e-mail. */
    @Mock
    private OttDelivery ottDelivery;

    /** Use case that sends SMS. */
    @Mock
    private SendSmsOneTimeCodeUseCase sendSmsOneTimeCodeUseCase;

    /** Real policy of the codes. */
    @Spy
    private OttPolicy ottPolicy = new OttPolicy(LENGTH, TTL, Duration.ofMinutes(15), 5);

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    @InjectMocks
    private RequestOneTimeCodeUseCase useCase;

    /**
     * Verifies that a known user gets a stored hash and an e-mail with the clear code.
     */
    @Test
    void execute_whenEmailDestinationExists_storesHashAndDeliversCode() {
        stubCode();
        when(clock.instant()).thenReturn(NOW);
        final var userId = UUID.randomUUID();
        when(resolveOttDestinationUseCase.execute(USERNAME, OttChannel.EMAIL))
                .thenReturn(Optional.of(new OttDestination(userId, OttChannel.EMAIL, EMAIL)));
        final var captor = ArgumentCaptor.<OneTimeCode>captor();

        final var result = useCase.execute(USERNAME, OttChannel.EMAIL, OttPurpose.LOGIN, BINDING);

        assertEquals(new OneTimeCodeRequestResult(true, TTL), result);
        verify(oneTimeCodeRepository).save(captor.capture());
        final var saved = captor.getValue();
        assertEquals(USERNAME, saved.username());
        assertEquals(HASH, saved.codeHash());
        assertEquals(BINDING, saved.bindingId());
        assertEquals(OttChannel.EMAIL, saved.channel());
        assertEquals(OttPurpose.LOGIN, saved.purpose());
        assertEquals(0, saved.attempts());
        assertEquals(NOW.plus(TTL), saved.expiresAt());
        verify(ottDelivery).deliverCode(OttChannel.EMAIL, EMAIL, CODE, TTL);
        verifyNoInteractions(sendSmsOneTimeCodeUseCase);
    }

    /**
     * Verifies that an SMS destination is served by the SMS use case, with the code in the text.
     */
    @Test
    void execute_whenSmsDestinationExists_sendsSms() {
        stubCode();
        when(clock.instant()).thenReturn(NOW);
        when(resolveOttDestinationUseCase.execute(USERNAME, OttChannel.SMS))
                .thenReturn(Optional.of(new OttDestination(UUID.randomUUID(), OttChannel.SMS, PHONE)));
        final var text = ArgumentCaptor.<String>captor();

        final var result = useCase.execute(USERNAME, OttChannel.SMS, OttPurpose.SECOND_FACTOR, BINDING);

        assertTrue(result.accepted());
        verify(oneTimeCodeRepository).save(any(OneTimeCode.class));
        verify(sendSmsOneTimeCodeUseCase).execute(eq(new PhoneNumber(PHONE)),
                text.capture());
        assertTrue(text.getValue().contains(CODE));
        verifyNoInteractions(ottDelivery);
    }

    /**
     * Verifies that an unknown, disabled or unverified identifier yields the very same result and nothing is stored
     * or sent.
     */
    @Test
    void execute_whenNoDestination_returnsSameResultAndStoresAndSendsNothing() {
        stubCode();
        when(resolveOttDestinationUseCase.execute(USERNAME, OttChannel.EMAIL)).thenReturn(Optional.empty());

        final var result = useCase.execute(USERNAME, OttChannel.EMAIL, OttPurpose.LOGIN, BINDING);

        assertEquals(new OneTimeCodeRequestResult(true, TTL), result);
        verifyNoInteractions(oneTimeCodeRepository, ottDelivery, sendSmsOneTimeCodeUseCase);
    }

    /**
     * Verifies that an e-mail delivery failure is not reported.
     */
    @Test
    void execute_whenEmailDeliveryFails_returnsSameResult() {
        stubCode();
        when(clock.instant()).thenReturn(NOW);
        when(resolveOttDestinationUseCase.execute(USERNAME, OttChannel.EMAIL))
                .thenReturn(Optional.of(new OttDestination(UUID.randomUUID(), OttChannel.EMAIL, EMAIL)));
        doThrow(new OttDeliveryException("mail is down", new IllegalStateException(CODE)))
                .when(ottDelivery).deliverCode(any(), anyString(), anyString(), any());

        final var result = useCase.execute(USERNAME, OttChannel.EMAIL, OttPurpose.LOGIN, BINDING);

        assertEquals(new OneTimeCodeRequestResult(true, TTL), result);
    }

    /**
     * Verifies that an SMS provider failure, a refused country and an exhausted budget are not reported.
     */
    @Test
    void execute_whenSmsIsRefusedOrFails_returnsSameResult() {
        stubCode();
        when(clock.instant()).thenReturn(NOW);
        when(resolveOttDestinationUseCase.execute(USERNAME, OttChannel.SMS))
                .thenReturn(Optional.of(new OttDestination(UUID.randomUUID(), OttChannel.SMS, PHONE)));
        doThrow(new SmsDeliveryException("provider down", new IllegalStateException()),
                new SmsCountryNotAllowedException(), new SmsBudgetExceededException())
                .when(sendSmsOneTimeCodeUseCase).execute(any(PhoneNumber.class), anyString());

        final var expected = new OneTimeCodeRequestResult(true, TTL);
        assertEquals(expected, useCase.execute(USERNAME, OttChannel.SMS, OttPurpose.LOGIN, BINDING));
        assertEquals(expected, useCase.execute(USERNAME, OttChannel.SMS, OttPurpose.LOGIN, BINDING));
        assertEquals(expected, useCase.execute(USERNAME, OttChannel.SMS, OttPurpose.LOGIN, BINDING));
    }

    /**
     * Stubs the generator and the hasher.
     */
    private void stubCode() {
        when(oneTimeCodeGenerator.generate(LENGTH)).thenReturn(CODE);
        when(oneTimeCodeHasher.hash(CODE)).thenReturn(HASH);
    }
}
