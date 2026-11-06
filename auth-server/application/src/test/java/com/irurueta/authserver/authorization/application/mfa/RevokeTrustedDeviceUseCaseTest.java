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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link RevokeTrustedDeviceUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class RevokeTrustedDeviceUseCaseTest {

    /** Port that stores the trusted devices. */
    @Mock
    private TrustedDeviceRepository trustedDeviceRepository;

    /** Use case that records the audit events. */
    @Mock
    private RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Use case under test. */
    @InjectMocks
    private RevokeTrustedDeviceUseCase useCase;

    /**
     * Verifies that revoking an existing device is audited.
     */
    @Test
    void execute_whenTheDeviceExists_revokesAndAudits() {
        final var userId = UUID.randomUUID();
        final var deviceId = UUID.randomUUID();
        when(trustedDeviceRepository.revoke(userId, deviceId)).thenReturn(true);

        assertTrue(useCase.execute(userId, "alice", deviceId));

        verify(recordSecurityEventUseCase).execute(SecurityEventType.TRUSTED_DEVICE_REVOKED, userId, "alice", null);
    }

    /**
     * Verifies that revoking a device that does not exist is not audited.
     */
    @Test
    void execute_whenTheDeviceDoesNotExist_returnsFalseWithoutAuditing() {
        final var userId = UUID.randomUUID();
        final var deviceId = UUID.randomUUID();
        when(trustedDeviceRepository.revoke(userId, deviceId)).thenReturn(false);

        assertFalse(useCase.execute(userId, "alice", deviceId));

        verifyNoInteractions(recordSecurityEventUseCase);
    }
}
