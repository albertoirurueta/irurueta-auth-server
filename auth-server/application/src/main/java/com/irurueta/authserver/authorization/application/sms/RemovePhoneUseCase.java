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

import com.irurueta.authserver.authorization.application.mfa.HasConfirmedSecondFactorUseCase;
import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
import com.irurueta.authserver.authorization.domain.sms.PhoneVerificationRepository;
import com.irurueta.authserver.authorization.domain.sms.UserPhoneRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Removes the phone of a user, verified and pending. Removing a verified phone removes a second factor, so it is
 * audited, and when that leaves the user without any confirmed second factor every trusted device of the user is
 * revoked too, as deleting the last passkey does: a remembered browser stands in for a second factor the user no
 * longer has.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class RemovePhoneUseCase {

    /** Detail of the audit event. */
    static final String AUDIT_DETAIL = "phone";

    /** Port that stores the verified phones. */
    private final UserPhoneRepository userPhoneRepository;

    /** Port that stores the pending verifications. */
    private final PhoneVerificationRepository phoneVerificationRepository;

    /** Use case telling whether the user still has a confirmed second factor. */
    private final HasConfirmedSecondFactorUseCase hasConfirmedSecondFactorUseCase;

    /** Port that stores the trusted devices. */
    private final TrustedDeviceRepository trustedDeviceRepository;

    /** Use case that records the audit events. */
    private final RecordSecurityEventUseCase recordSecurityEventUseCase;

    /**
     * Removes the phone and any pending verification of a user.
     *
     * @param userId   identifier of the user.
     * @param username name of the user, for the audit log.
     */
    public void execute(final UUID userId, final String username) {
        final var hadVerifiedPhone = userPhoneRepository.findByUserId(userId).isPresent();
        userPhoneRepository.deleteByUserId(userId);
        phoneVerificationRepository.deleteByUserId(userId);
        if (!hadVerifiedPhone) {
            return;
        }
        var detail = AUDIT_DETAIL;
        if (!hasConfirmedSecondFactorUseCase.execute(userId)) {
            final var revoked = trustedDeviceRepository.deleteByUser(userId);
            detail = detail + "; trusted devices revoked: " + revoked;
        }
        recordSecurityEventUseCase.execute(SecurityEventType.SECOND_FACTOR_REMOVED, userId, username, detail);
    }
}
