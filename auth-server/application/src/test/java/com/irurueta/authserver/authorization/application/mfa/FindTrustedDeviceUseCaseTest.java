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
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.mfa.TrustedDevice;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceRepository;
import com.irurueta.authserver.authorization.domain.mfa.TrustedDeviceTokenSigner;
import com.irurueta.authserver.authorization.domain.password.UserAccount;
import com.irurueta.authserver.authorization.domain.password.UserAccountRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
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

    /** Name of the user. */
    private static final String USERNAME = "alice";

    /** Signed value of the cookie. */
    private static final String COOKIE_VALUE = "raw.signature";

    /** Port that checks the signature of the cookie value. */
    @Mock
    private TrustedDeviceTokenSigner trustedDeviceTokenSigner;

    /** Port that provides the user accounts. */
    @Mock
    private UserAccountRepository userAccountRepository;

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
     * Verifies that a correctly signed value finds the device of the user by the hash of the raw token.
     */
    @Test
    void execute_whenSignatureIsValidAndTokenIsKnown_returnsTheDevice() {
        final var userId = UUID.randomUUID();
        final var device = new TrustedDevice(UUID.randomUUID(), userId, "hashed", null, NOW.plusSeconds(1), NOW);
        signedTokenOf(userId);
        when(trustedDeviceRepository.findUsable(userId, "hashed", NOW)).thenReturn(Optional.of(device));

        assertSame(device, useCase.execute(USERNAME, COOKIE_VALUE).orElseThrow());
    }

    /**
     * Verifies that an unknown token finds nothing.
     */
    @Test
    void execute_whenTokenIsUnknown_returnsEmpty() {
        final var userId = UUID.randomUUID();
        signedTokenOf(userId);
        when(trustedDeviceRepository.findUsable(userId, "hashed", NOW)).thenReturn(Optional.empty());

        assertTrue(useCase.execute(USERNAME, COOKIE_VALUE).isEmpty());
    }

    /**
     * Verifies that a device the port answers for another user is never returned.
     */
    @Test
    void execute_whenDeviceBelongsToAnotherUser_returnsEmpty() {
        final var userId = UUID.randomUUID();
        signedTokenOf(userId);
        when(trustedDeviceRepository.findUsable(userId, "hashed", NOW)).thenReturn(Optional.of(
                new TrustedDevice(UUID.randomUUID(), UUID.randomUUID(), "hashed", null, NOW.plusSeconds(1), NOW)));

        assertTrue(useCase.execute(USERNAME, COOKIE_VALUE).isEmpty());
    }

    /**
     * Verifies that a forged or unsigned value is rejected before the account or the device is looked up.
     */
    @Test
    void execute_whenSignatureIsInvalid_returnsEmptyWithoutLookingAnythingUp() {
        when(trustedDeviceTokenSigner.verify(COOKIE_VALUE)).thenReturn(Optional.empty());

        assertTrue(useCase.execute(USERNAME, COOKIE_VALUE).isEmpty());
        verifyNoInteractions(userAccountRepository, trustedDeviceRepository, trustedDeviceTokens, clock);
    }

    /**
     * Verifies that a valid value of a user that no longer exists finds nothing.
     */
    @Test
    void execute_whenAccountIsMissing_returnsEmpty() {
        when(trustedDeviceTokenSigner.verify(COOKIE_VALUE)).thenReturn(Optional.of("raw"));
        when(userAccountRepository.findByUsername(USERNAME)).thenReturn(Optional.empty());

        assertTrue(useCase.execute(USERNAME, COOKIE_VALUE).isEmpty());
        verifyNoInteractions(trustedDeviceRepository);
    }

    /**
     * Makes the signature valid and the account of the user exist.
     *
     * @param userId identifier of the account.
     */
    private void signedTokenOf(final UUID userId) {
        when(trustedDeviceTokenSigner.verify(COOKIE_VALUE)).thenReturn(Optional.of("raw"));
        when(userAccountRepository.findByUsername(USERNAME))
                .thenReturn(Optional.of(new UserAccount(userId, USERNAME, "hash", true, List.of())));
        when(clock.instant()).thenReturn(NOW);
        when(trustedDeviceTokens.hash("raw")).thenReturn("hashed");
    }
}
