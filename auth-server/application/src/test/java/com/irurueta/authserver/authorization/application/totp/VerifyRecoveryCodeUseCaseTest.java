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
import com.irurueta.authserver.authorization.domain.password.PasswordHasher;
import com.irurueta.authserver.authorization.domain.totp.RecoveryCode;
import com.irurueta.authserver.authorization.domain.totp.RecoveryCodeRepository;
import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

/**
 * Unit tests of {@link VerifyRecoveryCodeUseCase}.
 */
@ExtendWith(MockitoExtension.class)
class VerifyRecoveryCodeUseCaseTest {

    /** Current instant used by the tests. */
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    /** Port that stores the recovery codes. */
    @Mock
    private RecoveryCodeRepository recoveryCodeRepository;

    /** Port that hashes the codes. */
    @Mock
    private PasswordHasher passwordHasher;

    /** Normalizer of typed codes. */
    @Mock
    private RecoveryCodes recoveryCodes;

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
    private VerifyRecoveryCodeUseCase useCase;

    /**
     * Verifies that a locked second factor rejects the attempt without looking at the codes.
     */
    @Test
    void execute_whenLocked_throwsSecondFactorLockedException() {
        final var userId = UUID.randomUUID();
        when(checkSecondFactorLockoutUseCase.execute(userId)).thenReturn(true);

        assertThrows(SecondFactorLockedException.class, () -> useCase.execute(userId, "alice", "CODE"));

        verify(recoveryCodeRepository, never()).findUnused(userId);
    }

    /**
     * Verifies that a matching unused code is consumed, the failures cleared and the use audited.
     */
    @Test
    void execute_whenCodeMatches_consumesItAndResetsFailures() {
        final var userId = UUID.randomUUID();
        final var other = new RecoveryCode(UUID.randomUUID(), userId, "other", null);
        final var match = new RecoveryCode(UUID.randomUUID(), userId, "match", null);
        when(clock.instant()).thenReturn(NOW);
        when(recoveryCodes.normalize("abc")).thenReturn("ABC");
        when(recoveryCodeRepository.findUnused(userId)).thenReturn(List.of(other, match));
        when(passwordHasher.matches("ABC", "other")).thenReturn(false);
        when(passwordHasher.matches("ABC", "match")).thenReturn(true);
        when(recoveryCodeRepository.markUsed(match.id(), NOW)).thenReturn(true);

        assertTrue(useCase.execute(userId, "alice", "abc"));

        verify(resetSecondFactorFailuresUseCase).execute(userId);
        verify(recordSecurityEventUseCase).execute(SecurityEventType.RECOVERY_CODE_USED, userId, "alice", null);
    }

    /**
     * Verifies that every code is checked even after a match, so the time does not reveal the position.
     */
    @Test
    void execute_whenSeveralCodesMatch_checksAllAndConsumesTheFirst() {
        final var userId = UUID.randomUUID();
        final var first = new RecoveryCode(UUID.randomUUID(), userId, "first", null);
        final var second = new RecoveryCode(UUID.randomUUID(), userId, "second", null);
        when(clock.instant()).thenReturn(NOW);
        when(recoveryCodes.normalize("abc")).thenReturn("ABC");
        when(recoveryCodeRepository.findUnused(userId)).thenReturn(List.of(first, second));
        when(passwordHasher.matches("ABC", "first")).thenReturn(true);
        when(passwordHasher.matches("ABC", "second")).thenReturn(true);
        when(recoveryCodeRepository.markUsed(first.id(), NOW)).thenReturn(true);

        assertTrue(useCase.execute(userId, "alice", "abc"));

        verify(passwordHasher).matches("ABC", "second");
    }

    /**
     * Verifies that a wrong code counts as a failure.
     */
    @Test
    void execute_whenNoCodeMatches_registersAFailure() {
        final var userId = UUID.randomUUID();
        when(recoveryCodes.normalize("abc")).thenReturn("ABC");
        when(recoveryCodeRepository.findUnused(userId))
                .thenReturn(List.of(new RecoveryCode(UUID.randomUUID(), userId, "other", null)));
        when(passwordHasher.matches("ABC", "other")).thenReturn(false);

        assertFalse(useCase.execute(userId, "alice", "abc"));

        verify(registerSecondFactorFailureUseCase).execute(userId, "alice");
        verify(resetSecondFactorFailuresUseCase, never()).execute(userId);
    }

    /**
     * Verifies that a code consumed concurrently by another request counts as a failure.
     */
    @Test
    void execute_whenTheCodeWasJustConsumed_registersAFailure() {
        final var userId = UUID.randomUUID();
        final var match = new RecoveryCode(UUID.randomUUID(), userId, "match", null);
        when(clock.instant()).thenReturn(NOW);
        when(recoveryCodes.normalize("abc")).thenReturn("ABC");
        when(recoveryCodeRepository.findUnused(userId)).thenReturn(List.of(match));
        when(passwordHasher.matches("ABC", "match")).thenReturn(true);
        when(recoveryCodeRepository.markUsed(match.id(), NOW)).thenReturn(false);

        assertFalse(useCase.execute(userId, "alice", "abc"));

        verify(registerSecondFactorFailureUseCase).execute(userId, "alice");
    }

    /**
     * Verifies that a missing code is treated as an empty one.
     */
    @Test
    void execute_whenCodeIsNull_registersAFailure() {
        final var userId = UUID.randomUUID();
        when(recoveryCodes.normalize("")).thenReturn("");
        when(recoveryCodeRepository.findUnused(userId)).thenReturn(List.of());

        assertFalse(useCase.execute(userId, "alice", null));

        verify(registerSecondFactorFailureUseCase).execute(userId, "alice");
    }
}
