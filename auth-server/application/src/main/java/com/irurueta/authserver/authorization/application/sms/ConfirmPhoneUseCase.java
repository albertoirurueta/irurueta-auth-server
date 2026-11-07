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

import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
import com.irurueta.authserver.authorization.domain.ott.OneTimeCodeHasher;
import com.irurueta.authserver.authorization.domain.sms.PhoneVerification;
import com.irurueta.authserver.authorization.domain.sms.PhoneVerificationRepository;
import com.irurueta.authserver.authorization.domain.sms.UserPhone;
import com.irurueta.authserver.authorization.domain.sms.UserPhoneRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Confirms a phone with the code that was sent to it. Every way of failing returns the same {@code false}: no
 * pending verification, an expired or burnt code, a wrong code and a number that another user verified meanwhile.
 *
 * <p>Confirming a number other than the verified one replaces a second factor: the replacement is audited as the
 * removal of the old phone, and every trusted device of the user is revoked, as disabling TOTP does, because those
 * browsers were remembered in place of a factor the user no longer has.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class ConfirmPhoneUseCase {

    /** Start of the detail of the audit event of a replaced phone, followed by the number of revoked devices. */
    static final String REPLACED_DETAIL = "phone replaced; trusted devices revoked: ";

    /** Port that stores the verified phones. */
    private final UserPhoneRepository userPhoneRepository;

    /** Port that stores the pending verification. */
    private final PhoneVerificationRepository phoneVerificationRepository;

    /** Hasher of the verification code. */
    private final OneTimeCodeHasher oneTimeCodeHasher;

    /** Port that stores the trusted devices. */
    private final TrustedDeviceRepository trustedDeviceRepository;

    /** Use case that records the audit events. */
    private final RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** SMS settings. */
    private final SmsProperties smsProperties;

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Confirms the phone of a user.
     *
     * @param userId   identifier of the user.
     * @param username name of the user, for the audit log.
     * @param code     the code as typed.
     * @return {@code true} when the code was right and the phone is now verified.
     */
    public boolean execute(final UUID userId, final String username, final String code) {
        final var now = clock.instant();
        final var pending = phoneVerificationRepository.findByUserId(userId).orElse(null);
        if (pending == null) {
            return false;
        }
        if (pending.isExpiredAt(now)) {
            phoneVerificationRepository.deleteByUserId(userId);
            return false;
        }
        final var attempts = phoneVerificationRepository.incrementAttempts(userId);
        if (attempts > smsProperties.verificationMaxAttempts()) {
            phoneVerificationRepository.deleteByUserId(userId);
            return false;
        }
        if (!oneTimeCodeHasher.matches(code, pending.codeHash())) {
            if (attempts >= smsProperties.verificationMaxAttempts()) {
                phoneVerificationRepository.deleteByUserId(userId);
            }
            return false;
        }
        return verify(userId, username, pending, now);
    }

    /**
     * Stores the verified phone, clears the pending verification and handles the replacement of another number.
     *
     * @param userId   identifier of the user.
     * @param username name of the user, for the audit log.
     * @param pending  the verification that was confirmed.
     * @param now      the current instant.
     * @return {@code true} when the phone was stored, {@code false} when another user owns the number.
     */
    private boolean verify(final UUID userId, final String username, final PhoneVerification pending,
            final Instant now) {
        final var replaced = userPhoneRepository.findByUserId(userId)
                .filter(previous -> !previous.phone().equals(pending.phone()))
                .isPresent();
        final var stored = userPhoneRepository.save(new UserPhone(userId, pending.phone(), now));
        phoneVerificationRepository.deleteByUserId(userId);
        if (stored && replaced) {
            final var revoked = trustedDeviceRepository.deleteByUser(userId);
            recordSecurityEventUseCase.execute(SecurityEventType.SECOND_FACTOR_REMOVED, userId, username,
                    REPLACED_DETAIL + revoked);
        }
        return stored;
    }
}
