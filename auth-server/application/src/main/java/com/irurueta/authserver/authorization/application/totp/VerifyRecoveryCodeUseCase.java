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

import com.irurueta.authserver.authorization.application.mfa.CheckSecondFactorLockoutUseCase;
import com.irurueta.authserver.authorization.application.mfa.HasConfirmedSecondFactorUseCase;
import com.irurueta.authserver.authorization.application.mfa.RecordSecurityEventUseCase;
import com.irurueta.authserver.authorization.application.mfa.RegisterSecondFactorFailureUseCase;
import com.irurueta.authserver.authorization.application.mfa.ResetSecondFactorFailuresUseCase;
import com.irurueta.authserver.authorization.domain.mfa.SecondFactorLockedException;
import com.irurueta.authserver.authorization.domain.mfa.SecurityEventType;
import com.irurueta.authserver.authorization.domain.password.PasswordHasher;
import com.irurueta.authserver.authorization.domain.totp.RecoveryCode;
import com.irurueta.authserver.authorization.domain.totp.RecoveryCodeRepository;
import java.time.Clock;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that accepts a recovery code as a second factor. A code works once. Every stored code is checked, with no
 * early exit, so the time taken does not reveal which one matched; failures count towards the lockout. A user without
 * a confirmed second factor has no usable recovery code: the attempt fails and is counted.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class VerifyRecoveryCodeUseCase {

    /** Port that stores the recovery codes. */
    private final RecoveryCodeRepository recoveryCodeRepository;

    /** Port that hashes the codes like passwords. */
    private final PasswordHasher passwordHasher;

    /** Normalizer of typed codes. */
    private final RecoveryCodes recoveryCodes;

    /** Use case that tells whether the user has confirmed a second factor. */
    private final HasConfirmedSecondFactorUseCase hasConfirmedSecondFactorUseCase;

    /** Use case that tells whether the second factor is locked. */
    private final CheckSecondFactorLockoutUseCase checkSecondFactorLockoutUseCase;

    /** Use case that counts a failure. */
    private final RegisterSecondFactorFailureUseCase registerSecondFactorFailureUseCase;

    /** Use case that clears the failures. */
    private final ResetSecondFactorFailuresUseCase resetSecondFactorFailuresUseCase;

    /** Use case that records the audit events. */
    private final RecordSecurityEventUseCase recordSecurityEventUseCase;

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Verifies and consumes a recovery code.
     *
     * @param userId   identifier of the user.
     * @param username name of the user, for the audit log.
     * @param code     the code as typed.
     * @return {@code true} if the code was valid (and is now used up); {@code false} when it was not, or the user has
     *         no confirmed second factor.
     * @throws SecondFactorLockedException if the second factor of the user is locked.
     */
    public boolean execute(final UUID userId, final String username, final String code) {
        if (checkSecondFactorLockoutUseCase.execute(userId)) {
            throw new SecondFactorLockedException("The second factor is locked after too many failed attempts");
        }
        if (!hasConfirmedSecondFactorUseCase.execute(userId)) {
            registerSecondFactorFailureUseCase.execute(userId, username);
            return false;
        }
        final var normalized = recoveryCodes.normalize(code == null ? "" : code);
        Optional<RecoveryCode> match = Optional.empty();
        for (final var candidate : recoveryCodeRepository.findUnused(userId)) {
            final var matches = passwordHasher.matches(normalized, candidate.hashedCode());
            if (matches && match.isEmpty()) {
                match = Optional.of(candidate);
            }
        }
        if (match.isPresent() && recoveryCodeRepository.markUsed(match.get().id(), clock.instant())) {
            resetSecondFactorFailuresUseCase.execute(userId);
            recordSecurityEventUseCase.execute(SecurityEventType.RECOVERY_CODE_USED, userId, username, null);
            return true;
        }
        registerSecondFactorFailureUseCase.execute(userId, username);
        return false;
    }
}
