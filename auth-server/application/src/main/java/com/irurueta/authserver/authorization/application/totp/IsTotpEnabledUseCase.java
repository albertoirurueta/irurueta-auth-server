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

import com.irurueta.authserver.authorization.application.mfa.SecondFactorEnrolmentQuery;
import com.irurueta.authserver.authorization.domain.totp.TotpCredential;
import com.irurueta.authserver.authorization.domain.totp.TotpCredentialRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that tells whether a user has a confirmed authenticator app. It is also the TOTP
 * {@link SecondFactorEnrolmentQuery}, so a confirmed authenticator app makes the second factor required.
 */
@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class IsTotpEnabledUseCase implements SecondFactorEnrolmentQuery {

    /** Port that stores the TOTP credentials. */
    private final TotpCredentialRepository totpCredentialRepository;

    /**
     * Tells whether a user has a confirmed authenticator app.
     *
     * @param userId identifier of the user.
     * @return {@code true} when the user has a credential and it is confirmed; {@code false} for a pending enrolment.
     */
    public boolean execute(final UUID userId) {
        return totpCredentialRepository.findByUser(userId).filter(TotpCredential::confirmed).isPresent();
    }

    /**
     * Tells whether a user has confirmed the TOTP second factor.
     *
     * @param userId identifier of the user.
     * @return the same as {@link #execute(UUID)}.
     */
    @Override
    public boolean hasConfirmed(final UUID userId) {
        return execute(userId);
    }
}
