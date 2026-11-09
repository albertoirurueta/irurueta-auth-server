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
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

// tag::totp-verify[]
/**
 * Use case that verifies a TOTP code presented as a second factor: ±1 step window, no replay of a step already used,
 * lockout after repeated failures, and an audit event either way.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class VerifyTotpUseCase {

    /** Port that stores the TOTP credentials. */
    private final TotpCredentialRepository totpCredentialRepository;

    /** Port that decrypts the secrets. */
    private final TotpSecretCipher totpSecretCipher;

    /** The TOTP algorithm. */
    private final TotpAlgorithm totpAlgorithm;

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
     * Verifies a code.
     *
     * @param userId   identifier of the user.
     * @param username name of the user, for the audit log.
     * @param code     the code as typed.
     * @return {@code true} if the code is valid and fresh.
     * @throws SecondFactorLockedException if the second factor of the user is locked.
     */
    public boolean execute(final UUID userId, final String username, final String code) {
        if (checkSecondFactorLockoutUseCase.execute(userId)) {
            throw new SecondFactorLockedException("The second factor is locked after too many failed attempts");
        }
        final var accepted = totpCredentialRepository.findByUser(userId)
                .filter(TotpCredential::confirmed)
                .flatMap(credential -> totpAlgorithm.matchingStep(
                        totpSecretCipher.decrypt(credential.encryptedSecret()), code, clock.instant(),
                        credential.lastUsedStep()).stream().boxed().findFirst())
                .filter(step -> totpCredentialRepository.advanceLastUsedStep(userId, step))
                .isPresent();
        if (accepted) {
            resetSecondFactorFailuresUseCase.execute(userId);
            recordSecurityEventUseCase.execute(SecurityEventType.SECOND_FACTOR_SUCCESS, userId, username, "totp");
        } else {
            registerSecondFactorFailureUseCase.execute(userId, username);
        }
        return accepted;
    }
}
// end::totp-verify[]
