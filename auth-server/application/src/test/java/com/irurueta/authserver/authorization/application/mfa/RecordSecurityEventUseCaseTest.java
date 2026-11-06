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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.mfa.SecurityEvent;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventRepository;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import java.time.Clock;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link RecordSecurityEventUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class RecordSecurityEventUseCaseTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Port that stores the security events. */
    @Mock
    private SecurityEventRepository securityEventRepository;

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    @InjectMocks
    private RecordSecurityEventUseCase useCase;

    /**
     * Verifies that the event is stored with the current instant.
     */
    @Test
    void execute_whenCalled_storesTheEventStampedNow() {
        final var userId = UUID.randomUUID();
        when(clock.instant()).thenReturn(NOW);
        final var captor = ArgumentCaptor.<SecurityEvent>captor();

        useCase.execute(SecurityEventType.LOGIN_SUCCESS, userId, "alice", "detail");

        verify(securityEventRepository).store(captor.capture());
        assertEquals(new SecurityEvent(SecurityEventType.LOGIN_SUCCESS, userId, "alice", "detail", NOW),
                captor.getValue());
    }
}
