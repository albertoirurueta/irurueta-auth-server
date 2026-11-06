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

import com.irurueta.authserver.authorization.domain.mfa.SecurityEvent;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventRepository;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import java.time.Clock;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that records a security event (login, second factor, lockout, trusted device) in the audit log.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class RecordSecurityEventUseCase {

    /** Port that stores the security events. */
    private final SecurityEventRepository securityEventRepository;

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Records an event that happened now.
     *
     * @param type     kind of event.
     * @param userId   identifier of the user, or {@code null} when the user is unknown.
     * @param username name the user presented, or {@code null}.
     * @param detail   extra information, or {@code null}.
     */
    public void execute(
            final SecurityEventType type, final UUID userId, final String username, final String detail) {
        securityEventRepository.store(new SecurityEvent(type, userId, username, detail, clock.instant()));
    }
}
