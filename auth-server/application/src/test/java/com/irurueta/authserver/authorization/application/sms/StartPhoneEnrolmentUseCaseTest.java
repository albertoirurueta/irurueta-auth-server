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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeGenerator;
import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeHasher;
import com.irurueta.authserver.authorization.domain.sms.PhoneCountryResolver;
import com.irurueta.authserver.authorization.domain.sms.PhoneNormalizer;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.PhoneVerification;
import com.irurueta.authserver.authorization.domain.sms.PhoneVerificationRepository;
import com.irurueta.authserver.authorization.domain.sms.UserPhone;
import com.irurueta.authserver.authorization.domain.sms.UserPhoneRepository;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link StartPhoneEnrolmentUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class StartPhoneEnrolmentUseCaseTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Number as typed. */
    private static final String TYPED = "600 00 00 00";

    /** Normalised number. */
    private static final PhoneNumber PHONE = new PhoneNumber("+34600000000");

    /** Clear code from the mocked generator. */
    private static final String CODE = "123456";

    /** Hash from the mocked hasher. */
    private static final String HASH = "hash-of-code";

    /** Digits of the code. */
    private static final int LENGTH = 6;

    /** Validity of the code. */
    private static final Duration TTL = Duration.ofMinutes(10);

    /** Identifier of the user. */
    private static final UUID USER_ID = UUID.randomUUID();

    /** Port that normalises the number. */
    @Mock
    private PhoneNormalizer phoneNormalizer;

    /** Port that finds the country. */
    @Mock
    private PhoneCountryResolver phoneCountryResolver;

    /** Port that reads the verified phones. */
    @Mock
    private UserPhoneRepository userPhoneRepository;

    /** Port that stores the pending verification. */
    @Mock
    private PhoneVerificationRepository phoneVerificationRepository;

    /** Generator of the code. */
    @Mock
    private OneTimeCodeGenerator oneTimeCodeGenerator;

    /** Hasher of the code. */
    @Mock
    private OneTimeCodeHasher oneTimeCodeHasher;

    /** Use case that sends the message. */
    @Mock
    private SendSmsOneTimeCodeUseCase sendSmsOneTimeCodeUseCase;

    /** Real settings: Spain is served. */
    @Spy
    private SmsProperties smsProperties = new SmsProperties("ES", Set.of("ES"), null, 0L, null, 0L, 0L, LENGTH, TTL,
            0, null);

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    @InjectMocks
    private StartPhoneEnrolmentUseCase useCase;

    /**
     * Verifies that a free number gets its hash stored and the clear code sent.
     */
    @Test
    void execute_whenNumberIsFree_storesHashAndSendsCode() {
        stubNumber();
        stubCode();
        when(clock.instant()).thenReturn(NOW);
        when(userPhoneRepository.findByPhone(PHONE)).thenReturn(Optional.empty());
        final var saved = ArgumentCaptor.<PhoneVerification>captor();
        final var text = ArgumentCaptor.<String>captor();

        final var result = useCase.execute(USER_ID, TYPED);

        assertEquals(new PhoneEnrolmentStarted(TTL), result);
        verify(phoneVerificationRepository).save(saved.capture());
        assertEquals(HASH, saved.getValue().codeHash());
        assertEquals(PHONE, saved.getValue().phone());
        assertEquals(USER_ID, saved.getValue().userId());
        assertEquals(0, saved.getValue().attempts());
        assertEquals(NOW.plus(TTL), saved.getValue().expiresAt());
        verify(sendSmsOneTimeCodeUseCase).execute(eqPhone(), text.capture());
        assertEquals(SmsMessages.verificationCode(CODE, TTL), text.getValue());
    }

    /**
     * Verifies that re-enrolling the user's own verified number is allowed.
     */
    @Test
    void execute_whenNumberBelongsToSameUser_sendsCode() {
        stubNumber();
        stubCode();
        when(clock.instant()).thenReturn(NOW);
        when(userPhoneRepository.findByPhone(PHONE))
                .thenReturn(Optional.of(new UserPhone(USER_ID, PHONE, Instant.EPOCH)));

        useCase.execute(USER_ID, TYPED);

        verify(sendSmsOneTimeCodeUseCase).execute(eqPhone(), anyString());
    }

    /**
     * Verifies that a number owned by another user looks like a success but nothing is stored or sent.
     */
    @Test
    void execute_whenNumberBelongsToAnotherUser_returnsSameResultAndSendsNothing() {
        stubNumber();
        stubCode();
        when(userPhoneRepository.findByPhone(PHONE))
                .thenReturn(Optional.of(new UserPhone(UUID.randomUUID(), PHONE, Instant.EPOCH)));

        final var result = useCase.execute(USER_ID, TYPED);

        assertEquals(new PhoneEnrolmentStarted(TTL), result);
        verifyNoInteractions(phoneVerificationRepository, sendSmsOneTimeCodeUseCase);
    }

    /**
     * Verifies that an invalid number fails visibly.
     */
    @Test
    void execute_whenNumberIsInvalid_throwsInvalidPhoneNumberException() {
        when(phoneNormalizer.normalize(TYPED, "ES")).thenReturn(Optional.empty());

        assertThrows(InvalidPhoneNumberException.class, () -> useCase.execute(USER_ID, TYPED));

        verifyNoInteractions(phoneVerificationRepository, sendSmsOneTimeCodeUseCase);
    }

    /**
     * Verifies that an unknown or disallowed country fails visibly.
     */
    @Test
    void execute_whenCountryIsNotAllowed_throwsSmsCountryNotAllowedException() {
        when(phoneNormalizer.normalize(TYPED, "ES")).thenReturn(Optional.of(PHONE));
        when(phoneCountryResolver.countryOf(PHONE)).thenReturn(Optional.of("FR"), Optional.empty());

        assertThrows(SmsCountryNotAllowedException.class, () -> useCase.execute(USER_ID, TYPED));
        assertThrows(SmsCountryNotAllowedException.class, () -> useCase.execute(USER_ID, TYPED));

        verifyNoInteractions(phoneVerificationRepository, sendSmsOneTimeCodeUseCase);
    }

    /**
     * Verifies that an exhausted budget is not reported. (A provider failure cannot reach the use case: the message is
     * sent after the transaction commits.)
     */
    @Test
    void execute_whenSendingIsRefused_returnsSameResult() {
        stubNumber();
        stubCode();
        when(clock.instant()).thenReturn(NOW);
        when(userPhoneRepository.findByPhone(PHONE)).thenReturn(Optional.empty());
        doThrow(new SmsBudgetExceededException())
                .when(sendSmsOneTimeCodeUseCase).execute(any(PhoneNumber.class), anyString());

        assertEquals(new PhoneEnrolmentStarted(TTL), useCase.execute(USER_ID, TYPED));
    }

    /**
     * Matches the normalised phone.
     *
     * @return {@code null}, as Mockito matchers do.
     */
    private static PhoneNumber eqPhone() {
        return eq(PHONE);
    }

    /**
     * Stubs the normaliser and the country.
     */
    private void stubNumber() {
        when(phoneNormalizer.normalize(TYPED, "ES")).thenReturn(Optional.of(PHONE));
        when(phoneCountryResolver.countryOf(PHONE)).thenReturn(Optional.of("ES"));
    }

    /**
     * Stubs the generator and the hasher.
     */
    private void stubCode() {
        when(oneTimeCodeGenerator.generate(LENGTH)).thenReturn(CODE);
        when(oneTimeCodeHasher.hash(CODE)).thenReturn(HASH);
    }
}
