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

package com.irurueta.authserver.authorization.application.totp;

import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
import com.irurueta.authserver.authorization.domain.totp.RecoveryCodeRepository;
import com.irurueta.authserver.authorization.domain.totp.TotpCredentialRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

// tag::totp-disable[]
/**
 * Use case that removes the authenticator app of a user together with the recovery codes that went with it. Every
 * trusted device of the user is revoked as well, since a device trusted to skip a second factor must not outlive it,
 * and the removal is audited.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class DisableTotpUseCase {

    /** Port that stores the TOTP credentials. */
    private final TotpCredentialRepository totpCredentialRepository;

    /** Port that stores the recovery codes. */
    private final RecoveryCodeRepository recoveryCodeRepository;

    /** Port that stores the trusted devices. */
    private final TrustedDeviceRepository trustedDeviceRepository;

    /** Use case that records the audit events. */
    private final RecordSecurityEventUseCase recordSecurityEventUseCase;

    /**
     * Disables TOTP.
     *
     * @param userId   identifier of the user.
     * @param username name of the user, for the audit log.
     */
    public void execute(final UUID userId, final String username) {
        totpCredentialRepository.deleteByUser(userId);
        recoveryCodeRepository.deleteByUser(userId);
        final var revoked = trustedDeviceRepository.deleteByUser(userId);
        recordSecurityEventUseCase.execute(SecurityEventType.SECOND_FACTOR_REMOVED, userId, username,
                "totp; trusted devices revoked: " + revoked);
    }
}
// end::totp-disable[]
