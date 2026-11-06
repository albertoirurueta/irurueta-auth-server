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
import com.irurueta.authserver.authorization.domain.mfa.TrustedDevice;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
import java.time.Clock;
import java.time.Duration;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that trusts the browser of a user for some days so it skips the second factor. The raw token is returned
 * once; only its SHA-256 hash is stored.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class CreateTrustedDeviceUseCase {

    /** Port that stores the trusted devices. */
    private final TrustedDeviceRepository trustedDeviceRepository;

    /** Creator and hasher of the tokens. */
    private final TrustedDeviceTokens trustedDeviceTokens;

    /** Use case that records the audit events. */
    private final RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Source of the current time. */
    private final Clock clock;

    /** How long a device stays trusted ({@code authserver.mfa.trusted-device-validity}, default 30 days). */
    @Value("${authserver.mfa.trusted-device-validity:P30D}")
    private final Duration validity;

    /**
     * Trusts a device.
     *
     * @param userId           identifier of the user.
     * @param username         name of the user, for the audit log.
     * @param userAgentSummary short description of the browser, or {@code null}.
     * @return the device and its raw token.
     */
    public CreatedTrustedDevice execute(final UUID userId, final String username, final String userAgentSummary) {
        final var now = clock.instant();
        final var token = trustedDeviceTokens.newToken();
        final var device = new TrustedDevice(UUID.randomUUID(), userId, trustedDeviceTokens.hash(token),
                userAgentSummary, now.plus(validity), now);
        trustedDeviceRepository.store(device);
        recordSecurityEventUseCase.execute(SecurityEventType.TRUSTED_DEVICE_ADDED, userId, username, null);
        return new CreatedTrustedDevice(device, token);
    }
}
