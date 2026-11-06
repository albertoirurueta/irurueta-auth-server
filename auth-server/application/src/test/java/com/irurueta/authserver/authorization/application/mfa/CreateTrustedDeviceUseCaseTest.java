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

import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDevice;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceTokenSigner;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link CreateTrustedDeviceUseCase}, with real multi-factor settings.
 */
@ExtendWith(MockitoExtension.class)
class CreateTrustedDeviceUseCaseTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Validity used by the tests. */
    private static final Duration VALIDITY = Duration.ofDays(30);

    /** Failures that lock, unused here. */
    private static final int MAX_ATTEMPTS = 3;

    /** A duration unused here. */
    private static final Duration UNUSED = Duration.ofMinutes(5);

    /** Port that stores the trusted devices. */
    @Mock
    private TrustedDeviceRepository trustedDeviceRepository;

    /** Creator and hasher of the tokens. */
    @Mock
    private TrustedDeviceTokens trustedDeviceTokens;

    /** Port that signs the cookie value. */
    @Mock
    private TrustedDeviceTokenSigner trustedDeviceTokenSigner;

    /** Use case that records the audit events. */
    @Mock
    private RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Multi-factor settings. */
    @Spy
    private MfaProperties mfaProperties = new MfaProperties(MAX_ATTEMPTS, UNUSED, VALIDITY, "Issuer", UNUSED);

    /** Use case under test. */
    @InjectMocks
    private CreateTrustedDeviceUseCase useCase;

    /**
     * Verifies that the hash, never the raw token, is stored, and that the signed token is returned as the cookie
     * value.
     */
    @Test
    void execute_whenCalled_storesTheHashAndReturnsTheSignedToken() {
        final var userId = UUID.randomUUID();
        when(clock.instant()).thenReturn(NOW);
        when(trustedDeviceTokens.newToken()).thenReturn("raw");
        when(trustedDeviceTokens.hash("raw")).thenReturn("hashed");
        when(trustedDeviceTokenSigner.sign("raw")).thenReturn("raw.signature");
        final var captor = ArgumentCaptor.<TrustedDevice>captor();

        final var created = useCase.execute(userId, "alice", "Firefox");

        verify(trustedDeviceRepository).store(captor.capture());
        final var stored = captor.getValue();
        assertEquals("raw.signature", created.cookieValue());
        assertEquals(stored, created.device());
        assertEquals("hashed", stored.hashedToken());
        assertEquals(userId, stored.userId());
        assertEquals("Firefox", stored.userAgentSummary());
        assertEquals(NOW, stored.createdAt());
        assertEquals(NOW.plus(VALIDITY), stored.expiresAt());
        verify(recordSecurityEventUseCase).execute(SecurityEventType.TRUSTED_DEVICE_ADDED, userId, "alice", null);
    }
}
