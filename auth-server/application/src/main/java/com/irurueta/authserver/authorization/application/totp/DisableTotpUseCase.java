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

import com.irurueta.authserver.authorization.domain.totp.RecoveryCodeRepository;
import com.irurueta.authserver.authorization.domain.totp.TotpCredentialRepository;
import java.util.UUID;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Use case that removes the authenticator app of a user together with the recovery codes that went with it.
 */
@Service
@Transactional
@RequiredArgsConstructor
public class DisableTotpUseCase {

    /** Port that stores the TOTP credentials. */
    private final TotpCredentialRepository totpCredentialRepository;

    /** Port that stores the recovery codes. */
    private final RecoveryCodeRepository recoveryCodeRepository;

    /**
     * Disables TOTP.
     *
     * @param userId identifier of the user.
     */
    public void execute(final UUID userId) {
        totpCredentialRepository.deleteByUser(userId);
        recoveryCodeRepository.deleteByUser(userId);
    }
}
