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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.domain.totp.InvalidTotpCodeException;
import com.irurueta.authserver.authorization.domain.totp.TotpAlgorithm;
import com.irurueta.authserver.authorization.domain.totp.TotpAlreadyEnabledException;
import com.irurueta.authserver.authorization.domain.totp.TotpCredential;
import com.irurueta.authserver.authorization.domain.totp.TotpCredentialRepository;
import com.irurueta.authserver.authorization.domain.totp.TotpNotEnrolledException;
import com.irurueta.authserver.authorization.domain.totp.TotpSecretCipher;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link ConfirmTotpUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class ConfirmTotpUseCaseTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Encrypted secret of the stored credential. */
    private static final byte[] ENCRYPTED = {9, 9, 9};

    /** Clear secret returned by the mocked cipher. */
    private static final byte[] SECRET = {1, 2, 3};

    /** Step the mocked algorithm matches. */
    private static final long STEP = 42L;

    /** Port that stores the TOTP credentials. */
    @Mock
    private TotpCredentialRepository totpCredentialRepository;

    /** Port that decrypts the secrets. */
    @Mock
    private TotpSecretCipher totpSecretCipher;

    /** The TOTP algorithm. */
    @Mock
    private TotpAlgorithm totpAlgorithm;

    /** Use case that creates the recovery codes. */
    @Mock
    private GenerateRecoveryCodesUseCase generateRecoveryCodesUseCase;

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    @InjectMocks
    private ConfirmTotpUseCase useCase;

    /**
     * Verifies that a right code confirms the credential, stores the step and returns the recovery codes.
     */
    @Test
    void execute_whenTheCodeMatches_confirmsAndReturnsRecoveryCodes() {
        final var userId = UUID.randomUUID();
        final var codes = List.of("AAAAAAAAAA");
        when(clock.instant()).thenReturn(NOW);
        when(totpCredentialRepository.findByUser(userId)).thenReturn(Optional.of(
                new TotpCredential(userId, ENCRYPTED, false, TotpCredential.NEVER_USED, NOW)));
        when(totpSecretCipher.decrypt(ENCRYPTED)).thenReturn(SECRET);
        when(totpAlgorithm.matchingStep(SECRET, "123456", NOW, TotpCredential.NEVER_USED))
                .thenReturn(OptionalLong.of(STEP));
        when(generateRecoveryCodesUseCase.execute(userId)).thenReturn(codes);

        assertEquals(codes, useCase.execute(userId, "123456"));

        verify(totpCredentialRepository).advanceLastUsedStep(userId, STEP);
        verify(totpCredentialRepository).confirm(userId);
    }

    /**
     * Verifies that a wrong code is rejected and nothing is confirmed.
     */
    @Test
    void execute_whenTheCodeIsWrong_throwsInvalidTotpCodeException() {
        final var userId = UUID.randomUUID();
        when(clock.instant()).thenReturn(NOW);
        when(totpCredentialRepository.findByUser(userId)).thenReturn(Optional.of(
                new TotpCredential(userId, ENCRYPTED, false, TotpCredential.NEVER_USED, NOW)));
        when(totpSecretCipher.decrypt(ENCRYPTED)).thenReturn(SECRET);
        when(totpAlgorithm.matchingStep(SECRET, "000000", NOW, TotpCredential.NEVER_USED))
                .thenReturn(OptionalLong.empty());

        assertThrows(InvalidTotpCodeException.class, () -> useCase.execute(userId, "000000"));

        verify(totpCredentialRepository, never()).confirm(userId);
    }

    /**
     * Verifies that the non-throwing variant answers a wrong code with an empty result and confirms nothing.
     */
    @Test
    void tryConfirm_whenTheCodeIsWrong_returnsEmpty() {
        final var userId = UUID.randomUUID();
        when(clock.instant()).thenReturn(NOW);
        when(totpCredentialRepository.findByUser(userId)).thenReturn(Optional.of(
                new TotpCredential(userId, ENCRYPTED, false, TotpCredential.NEVER_USED, NOW)));
        when(totpSecretCipher.decrypt(ENCRYPTED)).thenReturn(SECRET);
        when(totpAlgorithm.matchingStep(SECRET, "000000", NOW, TotpCredential.NEVER_USED))
                .thenReturn(OptionalLong.empty());

        assertTrue(useCase.tryConfirm(userId, "000000").isEmpty());

        verify(totpCredentialRepository, never()).advanceLastUsedStep(userId, STEP);
        verify(totpCredentialRepository, never()).confirm(userId);
    }

    /**
     * Verifies that confirming without an enrolment fails.
     */
    @Test
    void execute_whenNothingWasEnrolled_throwsTotpNotEnrolledException() {
        final var userId = UUID.randomUUID();
        when(totpCredentialRepository.findByUser(userId)).thenReturn(Optional.empty());

        assertThrows(TotpNotEnrolledException.class, () -> useCase.execute(userId, "123456"));
    }

    /**
     * Verifies that confirming twice fails.
     */
    @Test
    void execute_whenAlreadyConfirmed_throwsTotpAlreadyEnabledException() {
        final var userId = UUID.randomUUID();
        when(totpCredentialRepository.findByUser(userId)).thenReturn(Optional.of(
                new TotpCredential(userId, ENCRYPTED, true, 0L, NOW)));

        assertThrows(TotpAlreadyEnabledException.class, () -> useCase.execute(userId, "123456"));
    }
}
