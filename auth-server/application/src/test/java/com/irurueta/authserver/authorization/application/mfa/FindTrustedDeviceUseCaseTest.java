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

import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.mfa.TrustedDevice;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link FindTrustedDeviceUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class FindTrustedDeviceUseCaseTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Port that stores the trusted devices. */
    @Mock
    private TrustedDeviceRepository trustedDeviceRepository;

    /** Creator and hasher of the tokens. */
    @Mock
    private TrustedDeviceTokens trustedDeviceTokens;

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    @InjectMocks
    private FindTrustedDeviceUseCase useCase;

    /**
     * Verifies that the device is looked up by the hash of the raw token.
     */
    @Test
    void execute_whenTheTokenIsKnown_returnsTheDevice() {
        final var userId = UUID.randomUUID();
        final var device = new TrustedDevice(UUID.randomUUID(), userId, "hashed", null, NOW.plusSeconds(1), NOW);
        when(clock.instant()).thenReturn(NOW);
        when(trustedDeviceTokens.hash("raw")).thenReturn("hashed");
        when(trustedDeviceRepository.findUsable(userId, "hashed", NOW)).thenReturn(Optional.of(device));

        assertSame(device, useCase.execute(userId, "raw").orElseThrow());
    }

    /**
     * Verifies that an unknown token finds nothing.
     */
    @Test
    void execute_whenTheTokenIsUnknown_returnsEmpty() {
        final var userId = UUID.randomUUID();
        when(clock.instant()).thenReturn(NOW);
        when(trustedDeviceTokens.hash("raw")).thenReturn("hashed");
        when(trustedDeviceRepository.findUsable(userId, "hashed", NOW)).thenReturn(Optional.empty());

        assertTrue(useCase.execute(userId, "raw").isEmpty());
    }
}
