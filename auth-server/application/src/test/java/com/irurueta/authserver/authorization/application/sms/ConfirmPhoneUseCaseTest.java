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
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeHasher;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.PhoneVerification;
import com.irurueta.authserver.authorization.domain.sms.PhoneVerificationRepository;
import com.irurueta.authserver.authorization.domain.sms.UserPhone;
import com.irurueta.authserver.authorization.domain.sms.UserPhoneRepository;
import java.time.Clock;
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
 * Unit tests of {@link ConfirmPhoneUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class ConfirmPhoneUseCaseTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Code typed by the user. */
    private static final String CODE = "123456";

    /** Stored hash. */
    private static final String HASH = "stored-hash";

    /** Attempts allowed. */
    private static final int MAX_ATTEMPTS = 3;

    /** Phone being verified. */
    private static final PhoneNumber PHONE = new PhoneNumber("+34600000000");

    /** Another phone, verified before. */
    private static final PhoneNumber PREVIOUS_PHONE = new PhoneNumber("+34600000001");

    /** Identifier of the user. */
    private static final UUID USER_ID = UUID.randomUUID();

    /** Name of the user. */
    private static final String USERNAME = "alice";

    /** Number of trusted devices revoked by a replacement. */
    private static final int REVOKED = 2;

    /** Port that stores the verified phones. */
    @Mock
    private UserPhoneRepository userPhoneRepository;

    /** Port that stores the pending verification. */
    @Mock
    private PhoneVerificationRepository phoneVerificationRepository;

    /** Hasher of the code. */
    @Mock
    private OneTimeCodeHasher oneTimeCodeHasher;

    /** Port that stores the trusted devices. */
    @Mock
    private TrustedDeviceRepository trustedDeviceRepository;

    /** Use case that records the audit events. */
    @Mock
    private RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Real settings with three attempts. */
    @Spy
    private SmsProperties smsProperties = new SmsProperties(null, null, null, 0L, null, 0L, 0L, 0, null, MAX_ATTEMPTS,
            null);

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    @InjectMocks
    private ConfirmPhoneUseCase useCase;

    /**
     * Verifies that a correct code stores the verified phone and clears the pending verification.
     */
    @Test
    void execute_whenCodeIsCorrect_savesPhoneAndDeletesVerification() {
        stubPending(NOW.plusSeconds(1));
        when(phoneVerificationRepository.incrementAttempts(USER_ID)).thenReturn(1);
        when(oneTimeCodeHasher.matches(CODE, HASH)).thenReturn(true);
        when(userPhoneRepository.save(any(UserPhone.class))).thenReturn(true);
        final var saved = ArgumentCaptor.<UserPhone>captor();

        assertTrue(useCase.execute(USER_ID, USERNAME, CODE));

        verify(userPhoneRepository).save(saved.capture());
        assertEquals(new UserPhone(USER_ID, PHONE, NOW), saved.getValue());
        verify(phoneVerificationRepository).deleteByUserId(USER_ID);
        verifyNoInteractions(trustedDeviceRepository, recordSecurityEventUseCase);
    }

    /**
     * Verifies that confirming a number that replaces another verified one revokes the trusted devices and audits
     * the removal of the old phone.
     */
    @Test
    void execute_whenNumberReplacesAnotherVerifiedOne_revokesTrustedDevicesAndAudits() {
        stubPending(NOW.plusSeconds(1));
        when(phoneVerificationRepository.incrementAttempts(USER_ID)).thenReturn(1);
        when(oneTimeCodeHasher.matches(CODE, HASH)).thenReturn(true);
        when(userPhoneRepository.findByUserId(USER_ID))
                .thenReturn(Optional.of(new UserPhone(USER_ID, PREVIOUS_PHONE, NOW.minusSeconds(1))));
        when(userPhoneRepository.save(any(UserPhone.class))).thenReturn(true);
        when(trustedDeviceRepository.deleteByUser(USER_ID)).thenReturn(REVOKED);

        assertTrue(useCase.execute(USER_ID, USERNAME, CODE));

        verify(recordSecurityEventUseCase).execute(SecurityEventType.SECOND_FACTOR_REMOVED, USER_ID, USERNAME,
                ConfirmPhoneUseCase.REPLACED_DETAIL + REVOKED);
    }

    /**
     * Verifies that confirming the number the user already has verified is not a replacement.
     */
    @Test
    void execute_whenNumberIsTheVerifiedOne_doesNotRevokeAnything() {
        stubPending(NOW.plusSeconds(1));
        when(phoneVerificationRepository.incrementAttempts(USER_ID)).thenReturn(1);
        when(oneTimeCodeHasher.matches(CODE, HASH)).thenReturn(true);
        when(userPhoneRepository.findByUserId(USER_ID))
                .thenReturn(Optional.of(new UserPhone(USER_ID, PHONE, NOW.minusSeconds(1))));
        when(userPhoneRepository.save(any(UserPhone.class))).thenReturn(true);

        assertTrue(useCase.execute(USER_ID, USERNAME, CODE));

        verifyNoInteractions(trustedDeviceRepository, recordSecurityEventUseCase);
    }

    /**
     * Verifies that a number verified by another user meanwhile fails like a wrong code.
     */
    @Test
    void execute_whenNumberIsTakenMeanwhile_returnsFalse() {
        stubPending(NOW.plusSeconds(1));
        when(phoneVerificationRepository.incrementAttempts(USER_ID)).thenReturn(1);
        when(oneTimeCodeHasher.matches(CODE, HASH)).thenReturn(true);
        when(userPhoneRepository.save(any(UserPhone.class))).thenReturn(false);

        assertFalse(useCase.execute(USER_ID, USERNAME, CODE));

        verify(phoneVerificationRepository).deleteByUserId(USER_ID);
        verifyNoInteractions(trustedDeviceRepository, recordSecurityEventUseCase);
    }

    /**
     * Verifies that a missing verification fails.
     */
    @Test
    void execute_whenNothingIsPending_returnsFalse() {
        when(clock.instant()).thenReturn(NOW);
        when(phoneVerificationRepository.findByUserId(USER_ID)).thenReturn(Optional.empty());

        assertFalse(useCase.execute(USER_ID, USERNAME, CODE));

        verifyNoInteractions(userPhoneRepository, oneTimeCodeHasher);
    }

    /**
     * Verifies that an expired verification is deleted and fails.
     */
    @Test
    void execute_whenVerificationIsExpired_deletesItAndReturnsFalse() {
        stubPending(NOW);

        assertFalse(useCase.execute(USER_ID, USERNAME, CODE));

        verify(phoneVerificationRepository).deleteByUserId(USER_ID);
        verifyNoInteractions(oneTimeCodeHasher);
    }

    /**
     * Verifies that a wrong code below the limit fails and keeps the verification.
     */
    @Test
    void execute_whenCodeIsWrongBelowLimit_returnsFalseAndKeepsVerification() {
        stubPending(NOW.plusSeconds(1));
        when(phoneVerificationRepository.incrementAttempts(USER_ID)).thenReturn(1);
        when(oneTimeCodeHasher.matches(CODE, HASH)).thenReturn(false);

        assertFalse(useCase.execute(USER_ID, USERNAME, CODE));

        verify(phoneVerificationRepository, never()).deleteByUserId(USER_ID);
        verifyNoInteractions(userPhoneRepository);
    }

    /**
     * Verifies that the last wrong attempt deletes the verification.
     */
    @Test
    void execute_whenLastAttemptIsWrong_deletesVerification() {
        stubPending(NOW.plusSeconds(1));
        when(phoneVerificationRepository.incrementAttempts(USER_ID)).thenReturn(MAX_ATTEMPTS);
        when(oneTimeCodeHasher.matches(CODE, HASH)).thenReturn(false);

        assertFalse(useCase.execute(USER_ID, USERNAME, CODE));

        verify(phoneVerificationRepository).deleteByUserId(USER_ID);
    }

    /**
     * Verifies that a counter past the limit deletes the verification without comparing the code.
     */
    @Test
    void execute_whenAttemptsExceedLimit_deletesWithoutComparing() {
        stubPending(NOW.plusSeconds(1));
        when(phoneVerificationRepository.incrementAttempts(USER_ID)).thenReturn(MAX_ATTEMPTS + 1);

        assertFalse(useCase.execute(USER_ID, USERNAME, CODE));

        verify(phoneVerificationRepository).deleteByUserId(USER_ID);
        verifyNoInteractions(oneTimeCodeHasher, userPhoneRepository);
    }

    /**
     * Stubs a pending verification.
     *
     * @param expiresAt when it expires.
     */
    private void stubPending(final Instant expiresAt) {
        when(clock.instant()).thenReturn(NOW);
        when(phoneVerificationRepository.findByUserId(USER_ID))
                .thenReturn(Optional.of(new PhoneVerification(USER_ID, PHONE, HASH, 0, expiresAt)));
    }
}
