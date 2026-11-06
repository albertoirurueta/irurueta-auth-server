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

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.irurueta.authserver.authorization.application.mfa.CheckSecondFactorLockoutUseCase;
import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.application.mfa.RegisterSecondFactorFailureUseCase;
import com.irurueta.authserver.authorization.application.mfa.ResetSecondFactorFailuresUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecondFactorLockedException;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.totp.TotpAlgorithm;
import com.irurueta.authserver.authorization.domain.totp.TotpCredential;
import com.irurueta.authserver.authorization.domain.totp.TotpCredentialRepository;
import com.irurueta.authserver.authorization.domain.totp.TotpSecretCipher;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link VerifyTotpUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class VerifyTotpUseCaseTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Encrypted secret of the stored credential. */
    private static final byte[] ENCRYPTED = {9, 9, 9};

    /** Clear secret returned by the mocked cipher. */
    private static final byte[] SECRET = {1, 2, 3};

    /** Step stored as the last used one. */
    private static final long LAST_STEP = 41L;

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

    /** Use case that tells whether the second factor is locked. */
    @Mock
    private CheckSecondFactorLockoutUseCase checkSecondFactorLockoutUseCase;

    /** Use case that counts a failure. */
    @Mock
    private RegisterSecondFactorFailureUseCase registerSecondFactorFailureUseCase;

    /** Use case that clears the failures. */
    @Mock
    private ResetSecondFactorFailuresUseCase resetSecondFactorFailuresUseCase;

    /** Use case that records the audit events. */
    @Mock
    private RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Source of the current time. */
    @Mock
    private Clock clock;

    /** Use case under test. */
    @InjectMocks
    private VerifyTotpUseCase useCase;

    /**
     * Verifies that a locked second factor throws before any code is checked.
     */
    @Test
    void execute_whenLocked_throwsSecondFactorLockedException() {
        final var userId = UUID.randomUUID();
        when(checkSecondFactorLockoutUseCase.execute(userId)).thenReturn(true);

        assertThrows(SecondFactorLockedException.class, () -> useCase.execute(userId, "alice", "123456"));

        verify(totpCredentialRepository, never()).findByUser(userId);
    }

    /**
     * Verifies that a fresh valid code is accepted, its step stored, the failures cleared and the success audited.
     */
    @Test
    void execute_whenTheCodeIsValid_acceptsAndStoresTheStep() {
        final var userId = UUID.randomUUID();
        stubCredential(userId, true);
        when(totpAlgorithm.matchingStep(SECRET, "123456", NOW, LAST_STEP)).thenReturn(OptionalLong.of(STEP));
        when(totpCredentialRepository.advanceLastUsedStep(userId, STEP)).thenReturn(true);

        assertTrue(useCase.execute(userId, "alice", "123456"));

        verify(resetSecondFactorFailuresUseCase).execute(userId);
        verify(recordSecurityEventUseCase)
                .execute(SecurityEventType.SECOND_FACTOR_SUCCESS, userId, "alice", "totp");
    }

    /**
     * Verifies that a code that does not match counts as a failure.
     */
    @Test
    void execute_whenTheCodeIsWrong_registersAFailure() {
        final var userId = UUID.randomUUID();
        stubCredential(userId, true);
        when(totpAlgorithm.matchingStep(SECRET, "000000", NOW, LAST_STEP)).thenReturn(OptionalLong.empty());

        assertFalse(useCase.execute(userId, "alice", "000000"));

        verify(registerSecondFactorFailureUseCase).execute(userId, "alice");
        verify(resetSecondFactorFailuresUseCase, never()).execute(userId);
    }

    /**
     * Verifies that a step consumed concurrently by another request counts as a failure (replay).
     */
    @Test
    void execute_whenTheStepWasJustUsed_registersAFailure() {
        final var userId = UUID.randomUUID();
        stubCredential(userId, true);
        when(totpAlgorithm.matchingStep(SECRET, "123456", NOW, LAST_STEP)).thenReturn(OptionalLong.of(STEP));
        when(totpCredentialRepository.advanceLastUsedStep(userId, STEP)).thenReturn(false);

        assertFalse(useCase.execute(userId, "alice", "123456"));

        verify(registerSecondFactorFailureUseCase).execute(userId, "alice");
    }

    /**
     * Verifies that a user without a confirmed authenticator app fails the verification.
     */
    @Test
    void execute_whenTheCredentialIsNotConfirmed_registersAFailure() {
        final var userId = UUID.randomUUID();
        when(totpCredentialRepository.findByUser(userId)).thenReturn(Optional.of(
                new TotpCredential(userId, ENCRYPTED, false, TotpCredential.NEVER_USED, NOW)));

        assertFalse(useCase.execute(userId, "alice", "123456"));

        verify(registerSecondFactorFailureUseCase).execute(userId, "alice");
    }

    /**
     * Stubs a stored credential, its decrypted secret and the clock.
     *
     * @param userId    identifier of the user.
     * @param confirmed whether the credential is confirmed.
     */
    private void stubCredential(final UUID userId, final boolean confirmed) {
        when(clock.instant()).thenReturn(NOW);
        when(totpCredentialRepository.findByUser(userId)).thenReturn(Optional.of(
                new TotpCredential(userId, ENCRYPTED, confirmed, LAST_STEP, NOW)));
        when(totpSecretCipher.decrypt(ENCRYPTED)).thenReturn(SECRET);
    }
}
