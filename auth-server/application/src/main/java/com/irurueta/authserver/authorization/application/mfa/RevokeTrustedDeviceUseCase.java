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

package com.irurueta.authserver.authorization.application.mfa;

import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that revokes a trusted device of a user, so it asks for the second factor again.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class RevokeTrustedDeviceUseCase {

    /** Port that stores the trusted devices. */
    private final TrustedDeviceRepository trustedDeviceRepository;

    /** Use case that records the audit events. */
    private final RecordSecurityEventUseCase recordSecurityEventUseCase;

    /**
     * Revokes a device; a device of another user is never touched.
     *
     * @param userId   identifier of the owner.
     * @param username name of the owner, for the audit log.
     * @param deviceId identifier of the device.
     * @return {@code true} if the device existed and was revoked.
     */
    public boolean execute(final UUID userId, final String username, final UUID deviceId) {
        final var revoked = trustedDeviceRepository.revoke(userId, deviceId);
        if (revoked) {
            recordSecurityEventUseCase.execute(SecurityEventType.TRUSTED_DEVICE_REVOKED, userId, username, null);
        }
        return revoked;
    }
}
