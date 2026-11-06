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

import com.irurueta.authserver.authorization.domain.totp.InvalidTotpCodeException;
import com.irurueta.authserver.authorization.domain.totp.TotpAlgorithm;
import com.irurueta.authserver.authorization.domain.totp.TotpAlreadyEnabledException;
import com.irurueta.authserver.authorization.domain.totp.TotpCredentialRepository;
import com.irurueta.authserver.authorization.domain.totp.TotpNotEnrolledException;
import com.irurueta.authserver.authorization.domain.totp.TotpSecretCipher;
import java.time.Clock;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that finishes the enrolment of an authenticator app with the first code it shows. The step of that code is
 * stored so it cannot be replayed, the credential is confirmed and the recovery codes are generated.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class ConfirmTotpUseCase {

    /** Port that stores the TOTP credentials. */
    private final TotpCredentialRepository totpCredentialRepository;

    /** Port that decrypts the secrets. */
    private final TotpSecretCipher totpSecretCipher;

    /** The TOTP algorithm. */
    private final TotpAlgorithm totpAlgorithm;

    /** Use case that creates the recovery codes. */
    private final GenerateRecoveryCodesUseCase generateRecoveryCodesUseCase;

    /** Source of the current time. */
    private final Clock clock;

    /**
     * Confirms the enrolment.
     *
     * @param userId identifier of the user.
     * @param code   the code shown by the authenticator app.
     * @return the clear-text recovery codes, to be shown once.
     * @throws TotpNotEnrolledException    if no enrolment was started.
     * @throws TotpAlreadyEnabledException if the enrolment was already confirmed.
     * @throws InvalidTotpCodeException    if the code is wrong.
     */
    public List<String> execute(final UUID userId, final String code) {
        return tryConfirm(userId, code).orElseThrow(() -> new InvalidTotpCodeException("The code is wrong"));
    }

    /**
     * Confirms the enrolment, answering a wrong code with an empty result instead of an exception, so that a caller
     * running in the same transaction can still count the failure (an exception leaving a transactional method marks
     * the whole transaction for rollback).
     *
     * @param userId identifier of the user.
     * @param code   the code shown by the authenticator app.
     * @return the clear-text recovery codes, to be shown once; empty when the code is wrong.
     * @throws TotpNotEnrolledException    if no enrolment was started.
     * @throws TotpAlreadyEnabledException if the enrolment was already confirmed.
     */
    public Optional<List<String>> tryConfirm(final UUID userId, final String code) {
        final var credential = totpCredentialRepository.findByUser(userId)
                .orElseThrow(() -> new TotpNotEnrolledException("No authenticator app is being enrolled"));
        if (credential.confirmed()) {
            throw new TotpAlreadyEnabledException("The authenticator app is already enabled");
        }
        final var secret = totpSecretCipher.decrypt(credential.encryptedSecret());
        final var step = totpAlgorithm.matchingStep(secret, code, clock.instant(), credential.lastUsedStep());
        if (step.isEmpty()) {
            return Optional.empty();
        }
        totpCredentialRepository.advanceLastUsedStep(userId, step.getAsLong());
        totpCredentialRepository.confirm(userId);
        return Optional.of(generateRecoveryCodesUseCase.execute(userId));
    }
}
