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

import com.irurueta.authserver.authorization.domain.mfa.TrustedDevice;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
import java.time.Clock;
import java.util.List;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that lists the trusted devices of a user that have not expired.
 */
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class ListTrustedDevicesUseCase {

    /** Port that stores the trusted devices. */
    private final TrustedDeviceRepository trustedDeviceRepository;

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Lists the devices.
     *
     * @param userId identifier of the user.
     * @return the devices, never {@code null}.
     */
    public List<TrustedDevice> execute(final UUID userId) {
        return trustedDeviceRepository.findByUser(userId, clock.instant());
    }
}
