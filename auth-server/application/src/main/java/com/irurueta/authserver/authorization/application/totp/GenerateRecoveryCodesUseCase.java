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

import com.irurueta.authserver.authorization.application.mfa.HasConfirmedSecondFactorUseCase;
import com.irurueta.authserver.authorization.domain.password.PasswordHasher;
import com.irurueta.authserver.authorization.domain.totp.RecoveryCode;
import com.irurueta.authserver.authorization.domain.totp.RecoveryCodeRepository;
import com.irurueta.authserver.authorization.domain.totp.TotpNotEnrolledException;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that creates a fresh set of recovery codes for a user, replacing any previous set. The clear-text codes
 * are returned once; only their hashes are stored. Recovery codes stand in for a second factor, so they are only
 * issued to a user who has confirmed one.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class GenerateRecoveryCodesUseCase {

    /** Number of codes in a set. */
    public static final int CODE_COUNT = 10;

    /** Port that stores the recovery codes. */
    private final RecoveryCodeRepository recoveryCodeRepository;

    /** Port that hashes the codes like passwords. */
    private final PasswordHasher passwordHasher;

    /** Creator of the codes. */
    private final RecoveryCodes recoveryCodes;

    /** Use case that tells whether the user has confirmed a second factor. */
    private final HasConfirmedSecondFactorUseCase hasConfirmedSecondFactorUseCase;

    /**
     * Generates the codes.
     *
     * @param userId identifier of the user.
     * @return the clear-text codes, to be shown to the user once.
     * @throws TotpNotEnrolledException if the user has no confirmed second factor.
     */
    public List<String> execute(final UUID userId) {
        if (!hasConfirmedSecondFactorUseCase.execute(userId)) {
            throw new TotpNotEnrolledException("Recovery codes need a confirmed authenticator app");
        }
        final var codes = Stream.generate(recoveryCodes::newCode).limit(CODE_COUNT).toList();
        recoveryCodeRepository.replaceAll(userId, codes.stream()
                .map(code -> new RecoveryCode(UUID.randomUUID(), userId, passwordHasher.encode(code), null))
                .toList());
        return codes;
    }
}
