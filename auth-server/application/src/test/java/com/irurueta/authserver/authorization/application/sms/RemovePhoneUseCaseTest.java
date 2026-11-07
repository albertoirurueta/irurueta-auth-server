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

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.mfa.HasConfirmedSecondFactorUseCase;
import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
import com.irurueta.authserver.authorization.domain.sms.PhoneNumber;
import com.irurueta.authserver.authorization.domain.sms.PhoneVerificationRepository;
import com.irurueta.authserver.authorization.domain.sms.UserPhone;
import com.irurueta.authserver.authorization.domain.sms.UserPhoneRepository;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link RemovePhoneUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class RemovePhoneUseCaseTest {

    /** Identifier of the user. */
    private static final UUID USER_ID = UUID.randomUUID();

    /** Name of the user. */
    private static final String USERNAME = "alice";

    /** Number of trusted devices revoked. */
    private static final int REVOKED = 3;

    /** Port that stores the verified phones. */
    @Mock
    private UserPhoneRepository userPhoneRepository;

    /** Port that stores the pending verifications. */
    @Mock
    private PhoneVerificationRepository phoneVerificationRepository;

    /** Use case telling whether the user still has a confirmed second factor. */
    @Mock
    private HasConfirmedSecondFactorUseCase hasConfirmedSecondFactorUseCase;

    /** Port that stores the trusted devices. */
    @Mock
    private TrustedDeviceRepository trustedDeviceRepository;

    /** Use case that records the audit events. */
    @Mock
    private RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Use case under test. */
    @InjectMocks
    private RemovePhoneUseCase useCase;

    /**
     * Verifies that removing the last second factor removes the verified phone and the pending verification, revokes
     * every trusted device and audits the removal.
     */
    @Test
    void execute_whenPhoneWasTheLastSecondFactor_revokesTrustedDevicesAndAudits() {
        stubVerifiedPhone();
        when(hasConfirmedSecondFactorUseCase.execute(USER_ID)).thenReturn(false);
        when(trustedDeviceRepository.deleteByUser(USER_ID)).thenReturn(REVOKED);

        useCase.execute(USER_ID, USERNAME);

        verify(userPhoneRepository).deleteByUserId(USER_ID);
        verify(phoneVerificationRepository).deleteByUserId(USER_ID);
        verify(recordSecurityEventUseCase).execute(SecurityEventType.SECOND_FACTOR_REMOVED, USER_ID, USERNAME,
                RemovePhoneUseCase.AUDIT_DETAIL + "; trusted devices revoked: " + REVOKED);
    }

    /**
     * Verifies that a user who keeps another second factor keeps the trusted devices, and the removal is audited.
     */
    @Test
    void execute_whenAnotherSecondFactorRemains_keepsTrustedDevicesAndAudits() {
        stubVerifiedPhone();
        when(hasConfirmedSecondFactorUseCase.execute(USER_ID)).thenReturn(true);

        useCase.execute(USER_ID, USERNAME);

        verifyNoInteractions(trustedDeviceRepository);
        verify(recordSecurityEventUseCase).execute(SecurityEventType.SECOND_FACTOR_REMOVED, USER_ID, USERNAME,
                RemovePhoneUseCase.AUDIT_DETAIL);
    }

    /**
     * Verifies that a user with only a pending verification has it removed, and that nothing is revoked or audited
     * because no second factor was removed.
     */
    @Test
    void execute_whenNoPhoneIsVerified_removesThePendingOneOnly() {
        when(userPhoneRepository.findByUserId(USER_ID)).thenReturn(Optional.empty());

        useCase.execute(USER_ID, USERNAME);

        verify(userPhoneRepository).deleteByUserId(USER_ID);
        verify(phoneVerificationRepository).deleteByUserId(USER_ID);
        verifyNoInteractions(hasConfirmedSecondFactorUseCase, trustedDeviceRepository, recordSecurityEventUseCase);
    }

    /**
     * Stubs a verified phone of the user.
     */
    private void stubVerifiedPhone() {
        when(userPhoneRepository.findByUserId(USER_ID))
                .thenReturn(Optional.of(new UserPhone(USER_ID, new PhoneNumber("+34600000000"), Instant.EPOCH)));
    }
}
